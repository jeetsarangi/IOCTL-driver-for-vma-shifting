#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/mm.h>
#include<linux/mm_types.h>
#include<linux/file.h>
#include<linux/fs.h>
#include<linux/path.h>
#include<linux/slab.h>
#include<linux/dcache.h>
#include<linux/sched.h>
#include<linux/uaccess.h>
#include<linux/fs_struct.h>
#include <asm/tlbflush.h>
#include<linux/uaccess.h>
#include<linux/device.h>
#include <linux/kthread.h> 
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include<linux/init.h>
#include "btplus.h"

#define PROT_READ 0x1
#define PROT_WRITE 0x2

#define MAP_FIXED 0x100		
#define MAP_ANONYMOUS 0x10	
#define MAP_PRIVATE	0x02

static int major;
atomic_t  device_opened;
static struct class *demo_class;
struct device *demo_device;

struct kobject *cs614_kobject;
unsigned promote = 0;

static ssize_t  sysfs_show(struct kobject *kobj,
                        struct kobj_attribute *attr, char *buf);
static ssize_t  sysfs_store(struct kobject *kobj,
                        struct kobj_attribute *attr,const char *buf, size_t count);

struct kobj_attribute sysfs_attr; 

struct address{
    unsigned long from_addr;
    unsigned long to_addr;
};

struct input{
    unsigned long addr;
    unsigned length;
    struct address * buff;
};

static int device_open(struct inode *inode, struct file *file)
{
        atomic_inc(&device_opened);
        try_module_get(THIS_MODULE);
        printk(KERN_INFO "Device opened successfully\n");
        return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
        atomic_dec(&device_opened);
        module_put(THIS_MODULE);
        printk(KERN_INFO "Device closed successfully\n");

        return 0;
}


static ssize_t device_read(struct file *filp,
                           char *buffer,
                           size_t length,
                           loff_t * offset){
    printk("read called\n");
    return 0;
}

static ssize_t
device_write(struct file *filp, const char *buff, size_t len, loff_t * off){
    
    printk("write called\n");
    return 8;
}


long device_ioctl(struct file *file,	
		 unsigned int ioctl_num,
		 unsigned long ioctl_param)
{
	//unsigned long addr = 1234;
	int ret = 0; // on failure return -1
	struct address * buff = NULL;
	unsigned long vma_addr = 0;
	unsigned long to_addr = 0;
	unsigned length = 0;
	struct input* ip;
	unsigned index = 0;
	struct address temp;


	// Jeet Declarations

	struct task_struct *task = current;
	struct mm_struct *mm = task->mm;

	struct vm_area_struct *o_vma,*n_vma;
	unsigned long len,end;
	char *d_buf;
	// Jeet Declarations end

	/*
	 * Switch according to the ioctl called
	 */
	switch (ioctl_num) {
	case IOCTL_MVE_VMA_TO:
	    buff = (struct address*)vmalloc(sizeof(struct address)) ;
	    printk("move VMA at a given address");
	    if(copy_from_user(buff,(char*)ioctl_param,sizeof(struct address))){
	        pr_err("MVE_VMA address write error\n");
		return ret;
	    }
	    vma_addr = buff->from_addr;
	    to_addr = buff->to_addr;
	    printk("address from :%lx, to:%lx \n",vma_addr,to_addr);


		////////// Jeet /////////////////

		o_vma = vma_lookup(mm, vma_addr);

		if(!o_vma){

			printk(KERN_INFO "The Specified VMA not found!!");
			return -1;

		}

		len = o_vma->vm_end - vma_addr;

		// Check to_addr
		if(vma_lookup(mm,to_addr)){

			printk(KERN_INFO "The to_addr VMA found!!");
			return -1;
		}

		if(vma_lookup(mm,to_addr+len-1)){

			printk(KERN_INFO "The to_addr+len VMA found!!");
			return -1;
		}


		ret = vm_mmap(NULL, to_addr, len, o_vma->vm_flags, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, 0);
		

		n_vma = vma_lookup(mm,to_addr);

		if(!n_vma)
			{
				printk(KERN_INFO" new vma not found");
				ret = -1;
				vfree(buff);
				return ret;
			}
		else
			{
				printk(KERN_INFO" new vma start = %lx  size = %ld\n",n_vma->vm_start,n_vma->vm_end-n_vma->vm_start);
				ret = 1;
			}

		d_buf = kmalloc(len,GFP_KERNEL);
		if(copy_from_user(d_buf,(char*)vma_addr, len))
		{
			ret = -1;
			printk(KERN_INFO"copy from user failed\n");
			vfree(buff);
			return ret;
		}
		
		if(copy_to_user((char*)to_addr, d_buf, len))
		{
			ret = -1;
			printk(KERN_INFO"copy to user failed\n");
			vfree(buff);
			return ret;
		}

		vm_munmap(o_vma->vm_start,o_vma->vm_end - o_vma->vm_start);
		printk(KERN_INFO "Unmap done!");

		////////// Jeet  ///////////////

	    vfree(buff);
	    return ret;
	case IOCTL_MVE_VMA:
	    buff = (struct address*)vmalloc(sizeof(struct address)) ;
	    printk("move VMA to available hole address");
	    if(copy_from_user(buff,(char*)ioctl_param,sizeof(struct address))){
	        pr_err("MVE_VMA address write error\n");
		return ret;
	    }
	    vma_addr = buff->from_addr;
	    printk("VMA address :%lx \n",vma_addr);


		///////////Jeet////////////////


		o_vma = vma_lookup(mm, vma_addr);

		printk(KERN_INFO "The old vma start = %lx end = %lx",o_vma->vm_start,o_vma->vm_end);

		if(!o_vma){

			printk(KERN_INFO "The Specified VMA not found!!");
			return -1;

		}

		end = o_vma->vm_end;
		len = end - vma_addr;

		for(n_vma = find_vma(mm,end) ; n_vma ; n_vma = find_vma(mm,end)){

			unsigned long hlen = n_vma->vm_start - end;
			
			printk(KERN_INFO "The hole Start = %lx End = %lx size = %lu",end,n_vma->vm_start,hlen);

			if(hlen >= len){

				ret = vm_mmap(NULL, end, len, o_vma->vm_flags, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, 0);

				n_vma = vma_lookup(mm, end);


				if(!n_vma)
				{

					printk("vma can't inserted\n");
					vfree(buff);
					return ret;

					
				}
				else
				{
					printk(KERN_INFO"vma found,%lx,%ld\n",n_vma->vm_start,n_vma->vm_end-n_vma->vm_start);
					ret = 1;
				}

				printk(KERN_INFO "The New_vma start = %lx",n_vma->vm_start);
				printk(KERN_INFO "The start of hole  = %lx",end);

				d_buf = kmalloc(len,GFP_KERNEL);
				if(copy_from_user(d_buf,(char*)vma_addr, len))
				{
					ret = -1;
					printk(KERN_INFO"copy from user failed\n");
					vfree(buff);
					return ret;
				}
				
				if(copy_to_user((char*)end, d_buf, len))
				{
					ret = -1;
					printk(KERN_INFO"copy to user failed\n");
					vfree(buff);
					return ret;
				}

				vm_munmap(o_vma->vm_start,o_vma->vm_end- o_vma->vm_start);

				buff->to_addr = end;
				if(copy_to_user((char*)ioctl_param,buff,sizeof(struct address)))
				{	
					printk("copy to user failed\n");
					ret = -1;
					vfree(buff);
					return ret;
				}

				vfree(buff);
				return ret;

			}

			end = n_vma->vm_end;
			printk(KERN_INFO "The VMA start = %lx end = %lx size = %lx",n_vma->vm_start,n_vma->vm_end,n_vma->vm_end-n_vma->vm_start);



		}

		printk(KERN_INFO "No hole is found!!");
		ret = -1;
		//////////Jeet////////////////

	    vfree(buff);
	    return ret;
        
	}
	return ret;
}


static struct file_operations fops = {
        .read = device_read,
        .write = device_write,
	.unlocked_ioctl = device_ioctl,
        .open = device_open,
        .release = device_release,
};

static char *demo_devnode(struct device *dev, umode_t *mode)
{
        if (mode && dev->devt == MKDEV(major, 0))
                *mode = 0666;
        return NULL;
}

//Implement required logic
static ssize_t sysfs_show(struct kobject *kobj, struct kobj_attribute *attr,
                      char *buf)
{
    pr_info("sysfs read\n"); 
    return 0;
}

//Implement required logic
static ssize_t sysfs_store(struct kobject *kobj, struct kobj_attribute *attr,
                     const char *buf, size_t count)
{
    printk("sysfs write\n");
    return count;
}



int init_module(void)
{
        int err;
	printk(KERN_INFO "Hello kernel\n");
        major = register_chrdev(0, DEVNAME, &fops);
        err = major;
        if (err < 0) {      
             printk(KERN_ALERT "Registering char device failed with %d\n", major);   
             goto error_regdev;
        }                 
        
        demo_class = class_create(THIS_MODULE, DEVNAME);
        err = PTR_ERR(demo_class);
        if (IS_ERR(demo_class))
                goto error_class;

        demo_class->devnode = demo_devnode;

        demo_device = device_create(demo_class, NULL,
                                        MKDEV(major, 0),
                                        NULL, DEVNAME);
        err = PTR_ERR(demo_device);
        if (IS_ERR(demo_device))
                goto error_device;
 
        printk(KERN_INFO "I was assigned major number %d. To talk to\n", major);                                                              
        atomic_set(&device_opened, 0);
        
	cs614_kobject = kobject_create_and_add("kobject_cs614", kernel_kobj);
        
	if(!cs614_kobject)
            return -ENOMEM;
	
	sysfs_attr.attr.name = "promote";
	sysfs_attr.attr.mode = 0666;
	sysfs_attr.show = sysfs_show;
	sysfs_attr.store = sysfs_store;

	err = sysfs_create_file(cs614_kobject, &(sysfs_attr.attr));
	if (err){
	    pr_info("sysfs exists:");
	    goto r_sysfs;
	}
	return 0;
r_sysfs:
	kobject_put(cs614_kobject);
        sysfs_remove_file(kernel_kobj, &sysfs_attr.attr);
error_device:
         class_destroy(demo_class);
error_class:
        unregister_chrdev(major, DEVNAME);
error_regdev:
        return  err;
}

void cleanup_module(void)
{
        device_destroy(demo_class, MKDEV(major, 0));
        class_destroy(demo_class);
        unregister_chrdev(major, DEVNAME);
	kobject_put(cs614_kobject);
	sysfs_remove_file(kernel_kobj, &sysfs_attr.attr);
	printk(KERN_INFO "Goodbye kernel\n");
}

MODULE_AUTHOR("cs614");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("assignment2");
