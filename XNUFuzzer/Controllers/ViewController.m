//
//  ViewController.m
//  XNUFuzzer
//
//  Created by Sem Voigtländer on 5/19/18.
//  Copyright © 2018 Sem Voigtländer. All rights reserved.
//

#import "ViewController.h"
#include "jailbreak.h"
extern char* stdoutPath;
extern boolean_t debuggerAttached;
NSTimer* timer;

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UITextView *logView;
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [[UIApplication sharedApplication] setIdleTimerDisabled:YES];
    if(!debuggerAttached) {
        timer = [NSTimer scheduledTimerWithTimeInterval:0.5f repeats:YES block:^(NSTimer *timer){
            
            NSString* contents_out = @"";
            contents_out = [[NSString alloc] initWithContentsOfFile:[NSString stringWithUTF8String:stdoutPath]];
            
            [self performSelectorOnMainThread:@selector(updateUI:) withObject:contents_out waitUntilDone:NO];
        }];
    }
    // Do any additional setup after loading the view, typically from a nib.
}

- (void)viewDidAppear:(BOOL)animated {
    if(debuggerAttached) {
        self.logView.text = @"Thanks for debugging me in Xcode";
    }
    [NSThread detachNewThreadWithBlock:^(void){
        jb_go();
        if(!debuggerAttached) {
            [timer invalidate];
        }
    }];
    
}

-(void)updateUI:(NSString*)contents{
    self.logView.text = contents;
    [self.logView scrollRangeToVisible:NSMakeRange(self.logView.text.length, 0)];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
