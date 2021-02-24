//
//  ViewController.m
//  FishHookDemo
//
//  Created by yxk on 2021/2/23.
//

#import "ViewController.h"
#import "fishhook.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    NSLog(@"第一次打印");
    NSLog(@"第二次打印");
    
    //rebinding结构体
    struct rebinding nslog;
    nslog.name = "NSLog";
    nslog.replacement = myNslog;
    nslog.replaced = (void *)&sys_nslog;
    //rebinding结构体数组
    struct rebinding rebs[1] = {nslog};
    /*
     *存放rebinding结构体的数组
     *数组的长度
     */
    rebind_symbols(rebs, 1);
    
    // Do any additional setup after loading the view.
}

//------更改NSLog---------
//函数指针
static void(*sys_nslog)(NSString *format, ...);
//定义一个新函数
void myNslog(NSString *format, ...) {
    format = [format stringByAppendingString:@"鱼上钩了！\n"];
    //调用原始的NSLog
    sys_nslog(format);
}

-(void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    NSLog(@"点击屏幕打印");
}


@end
