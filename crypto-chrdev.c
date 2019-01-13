/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-cryptodev device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <asm/uaccess.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

#define MSG_LEN 100

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	unsigned int *syscall_type,*syscall_ret;
	struct scatterlist syscall_type_sg,syscall_ret_sg,host_fd_sg,*sgs[3];
	int *host_fd,num_out=0,num_in=0;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_OPEN;
	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = -1;

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;
	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg,host_fd,sizeof(int));
	sgs[num_out+num_in++]=&host_fd_sg;

	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	spin_lock_irq(&crdev->lock);
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);

	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	spin_unlock_irq(&crdev->lock);
	crof->host_fd=*host_fd;

	/* If host failed to open() return -ENODEV. */
	if(host_fd<0){
		ret=-ENODEV;
		goto fail;
	}

fail:
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0,err,host_fd;
	unsigned int len;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int *syscall_type;
	unsigned int num_out=0,num_in=0;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg,host_fd_sg,*sgs[2];

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_CLOSE;
	host_fd=crof->host_fd;
	/**
	 * Send data to the host.
	 **/
	/* ?? */
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, &host_fd, sizeof(int));
	sgs[num_out++] = &host_fd_sg;
	
	spin_lock_irq(&crdev->lock);
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL) ;/*maybe not*/
		/* do nothing */
	spin_unlock_irq(&crdev->lock);

	kfree(crof);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	long ret = 0;
	int err,host_fd;
	__u32 *id_user_arg,id_arg;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, syscall_cmd_sg, output_msg_sg,dst_sg,
			input_msg_sg,sess_sg,cryp_sg,ret_sg,host_fd_sg,*sgs[7];
	unsigned int num_out, num_in, len,host_ret;
	unsigned char *output_msg, *input_msg ,*cryp_dst,*dst;
	unsigned int *syscall_type;
	struct session_op *sess_user_arg,sess_arg;
	struct crypt_op *cryp_user_arg,cryp_arg,*crypt_host;

	debug("Entering");

	/**
	 * Allocate all data that will be sent to the host.
	 **/
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_IOCTL;
	output_msg = kzalloc(MSG_LEN, GFP_KERNEL);
	input_msg = kzalloc(MSG_LEN, GFP_KERNEL);
	host_fd=crof->host_fd;

	num_out = 0;
	num_in = 0;
	sess_user_arg=NULL;
	cryp_user_arg=NULL;
	id_user_arg=NULL;
	cryp_dst=NULL;
	dst=NULL;
	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	sg_init_one(&syscall_cmd_sg,&cmd,sizeof(unsigned int));
	sgs[num_out++] = &syscall_cmd_sg;
	/* ?? */

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
	case CIOCGSESSION:
		debug("CIOCGSESSION");
		// memcpy(output_msg, "Hello HOST from ioctl CIOCGSESSION.", 36);
		input_msg[0] = '\0';
		sess_user_arg = (struct session_op*)arg;	/*get argument from syscall type session_op ptr*/
		ret=copy_from_user(&sess_arg,sess_user_arg,sizeof(struct session_op));
		if(ret) return -EFAULT;
		sg_init_one(&host_fd_sg,&host_fd,sizeof(int));
		sgs[num_out++]=&host_fd_sg;
		sg_init_one(&sess_sg, &sess_arg, sizeof(struct session_op));
		sgs[num_out+num_in++]=&sess_sg;	/*returns new session ptr*/
	
		break;

	case CIOCFSESSION:
		debug("CIOCFSESSION");
		id_user_arg = (__u32*)arg;	/*CIOCFSESSION has argument the sess_id*/
		ret=copy_from_user(&id_arg,id_user_arg,sizeof(__u32));
		if(ret) return -EFAULT;
		sg_init_one(&sess_sg, &id_arg, sizeof(__u32));
		sgs[num_out++]=&sess_sg;
		sg_init_one(&host_fd_sg,&host_fd,sizeof(int));
		sgs[num_out++]=&host_fd_sg;
		
		break;

	case CIOCCRYPT:
		debug("CIOCCRYPT");
		cryp_user_arg = (struct crypt_op*)arg;	 /*get argument from syscall type crypt_op*/
		ret=copy_from_user(&cryp_arg,cryp_user_arg,sizeof(struct crypt_op));
		if(ret) return -EFAULT;
		sg_init_one(&cryp_sg, &cryp_arg, sizeof(struct crypt_op));
		sgs[num_out++]=&cryp_sg;
		sg_init_one(&host_fd_sg,&host_fd,sizeof(int));
		sgs[num_out++]=&host_fd_sg;
		cryp_dst=kzalloc(cryp_arg.len*sizeof(unsigned char),GFP_KERNEL);
		dst=kzalloc(cryp_arg.len*sizeof(unsigned char),GFP_KERNEL);
		cryp_dst=cryp_arg.dst;
		ret=copy_from_user(dst,cryp_dst,cryp_arg.len*sizeof(unsigned char));
		if(ret) return -EFAULT;
		sg_init_one(&dst_sg,dst,cryp_arg.len*sizeof(unsigned char));
		sgs[num_out+num_in++]=&dst_sg;

		break;

	default:
		debug("Unsupported ioctl command");
		return -EINVAL;
	}

	sg_init_one(&ret_sg, &host_ret, sizeof(int));	/*return value of ioctl in host*/
	sgs[num_out+num_in++]=&ret_sg;
	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	/* ?? Lock ?? */
	spin_lock_irq(&crdev->lock);
	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	
	switch(cmd){
		case CIOCGSESSION:
			ret=copy_to_user(id_user_arg,&id_arg,sizeof(__u32));
			if(ret) return -EFAULT;
		case CIOCCRYPT:
			ret=copy_to_user(cryp_user_arg->dst,dst,cryp_arg.len*sizeof(unsigned char));
			if(ret) return -EFAULT;
	}
	spin_unlock_irq(&crdev->lock);
	ret=host_ret;
	if(ret)
		debug("ioctl failed");
	kfree(cryp_dst);
	kfree(syscall_type);

	debug("Leaving");

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
