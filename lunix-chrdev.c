/*
 * lunix-chrdev.c
 *
 * Implementation of character devices
 * for Lunix:TNG
 *
 * < device name >
 *
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"
#include "linux/thread_info.h"

#define current (current_thread_info()->task) /* get pid of current process */

struct state lunix_chrdev_state;

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	
	WARN_ON ( !(sensor = state->sensor));

	/* The following return is bogus, just for the stub to compile */
	return !((sensor->msr_data[state->type]).last_update==state->buf_timestamp);
}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	uint32_t current_values[];
	uint32_t current_last_update;
	uint32_t int_msr, dec_msr;
	long msr;

	debug("leaving\n");

	sensor=state->sensor;
	spin_lock(sensor->lock);
	
	/*
	 * Grab the raw data quickly, hold the
	 * spinlock for as little as possible.
	 */
	current_values[BATT]=sensor->msr_data[BATT]->values[0];
	current_values[TEMP]=sensor->msr_data[TEMP]->values[0];
	current_values[LIGHT]=sensor->msr_data[LIGHT]->values[0];
	current_last_update=sensor->msr_data[state->type]->last_update;
	
	/*
	 * Any new data available?
	 */
	if(current_last_update==state->buf_timestamp) {
		spin_unlock(sensor->lock);
		return -EAGAIN;}
	spin_unlock(sensor->lock);

	/*
	 * Now we can take our time to format them,
	 * holding only the private state semaphore
	 */
	switch(state->type){
		case(BATT):
			msr = lookup_voltage(current_values[BATT]);
			int_msr = msr/1000;
			dec_msr = msr%1000;
			sprintf(buf_data, "%ld,%ld", int_msr, dec_msr);
		case(TEMP):
			msr = lookup_temperature(current_values[TEMP]);
			int_msr = msr/1000;
			dec_msr = msr%1000;
			sprintf(buf_data, "%ld,%ld", int_msr, dec_msr);
		case(LIGHT):
			msr = lookup_light(current_values[LIGHT]);
			int_msr = msr/1000;
			dec_msr = msr%1000;
			sprintf(buf_data, "%ld,%ld", int_msr, dec_msr);
	}
	

	debug("leaving\n");
	return 0;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	struct lunix_chrev_state_struct *state;
	int ret,minor,major;

	debug("entering\n");
	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;

	/*
	 * Associate this open file with the relevant sensor based on
	 * the minor number of the device node [/dev/sensor<NO>-<TYPE>]
	 */
	minor=iminor(inode);
	major=imajor(inode);
	
	/* Allocate a new Lunix character device private state structure */
	state=kmalloc(sizeof(lunix_chrev_state_struct),GFP_KERNEL);
	filp->private_data=state;
	filp->private_data->sessor=lunix_sensor[(minor-filp->private_data->type)/8]
	filp->private_data->buf_timestamp=0

out:
	debug("leaving, with ret = %d\n", ret);
	return ret;
}

static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{
	kfree(state);
	return 0;
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{	
	/* Why? */
	return -EINVAL;
}

static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	ssize_t ret;

	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	state = filp->private_data;
	WARN_ON(!state);
	lunix_sensor_init(sensor);
	sensor = state->sensor;

	WARN_ON(!sensor);

	/* Lock? */
	down(state->lock);
	/*
	 * If the cached character device state needs to be
	 * updated by actual sensor data (i.e. we need to report
	 * on a "fresh" measurement, do so
	 */

	if (*f_pos == 0) {
		while (lunix_chrdev_state_update(state) == -EAGAIN) {
				/* ? */
				/* The process needs to sleep */
				/* See LDD3, page 153 for a hint */
			up(state->lock);
			wait_event_interruptible(sensor->wq,lunix_chrdev_state_needs_refresh(state)); /* sends current proc to sleep */
			down(state->lock);
		}
	}

	/* End of file */
	/* ? */
	
	/* Determine the number of cached bytes to copy to userspace */
	buf_lim = strlen((char*) buf_data);
	while(buf_lim){copy_to_user(/*user_buf*/, buf_data, buf_lim);}

	/* Auto-rewind on EOF mode? */
	/* ? */
out:
	/* Unlock? */
	up(state->lock);

	return ret;
}

static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return -EINVAL;
}

static struct file_operations lunix_chrdev_fops = 
{
    .owner          = THIS_MODULE,
	.open           = lunix_chrdev_open,
	.release        = lunix_chrdev_release,
	.read           = lunix_chrdev_read,
	.unlocked_ioctl = lunix_chrdev_ioctl,
	.mmap           = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements / sensor)
	 * beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
	
	spin_lock_init(lock);
	debug("initializing character device\n");
	cdev_init(&(lunix_chrdev_state->lunix_chrdev_cdev), &lunix_chrdev_fops);
	lunix_chrdev_state->lunix_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	/* register_chrdev_region? */
	ret=register_chrdev_region(dev_no,lunix_minor_cnt,"snoopy"); /*device name???*/
	if (ret < 0) {
		debug("failed to register region, ret = %d\n", ret);
		goto out;
	}	
	/* cdev_add? */
	ret=cdev_add(lunix_chrdev_state->lunix_chrdev_cdev,dev_no,lunix_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device\n");
		goto out_with_chrdev_region;
	}
	debug("completed successfully\n");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
	return ret;
}

void lunix_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
		
	debug("entering\n");
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	cdev_del(&lunix_chrdev_cdev);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
	debug("leaving\n");
}
