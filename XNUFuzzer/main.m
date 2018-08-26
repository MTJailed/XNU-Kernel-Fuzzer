//
//  main.m
//  XNUFuzzer
//
//  Created by Sem Voigtländer on 5/19/18.
//  Copyright © 2018 Sem Voigtländer. All rights reserved.
//

#import <UIKit/UIKit.h>
#include <unistd.h>
#import "AppDelegate.h"
#import "fuzzer.h"

char* stdoutPath = NULL;
boolean_t debuggerAttached = false;
int DebuggerAttached(void) {
    return getppid() != 1;
}

int redirectOutputs()
{
    setvbuf(stdout, 0, 2, 0); //make equal buffer types
    setvbuf(stderr, 0, 2, 0); //make equal buffer types
    close(STDOUT_FILENO); //close the previous file descriptors
    close(STDERR_FILENO);
    FILE* f = fopen(stdoutPath, "a+"); //open the log file
    dup2(fileno(stdout), fileno(stderr)); //redirect stderr to stdout
    dup2(fileno(stdout), fileno(f)); //redirect stdout to the log file
    return 1;
}

int main(int argc, char * argv[]) {
    stdoutPath = (char*)[[[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject] stringByAppendingString:@"/stdout"] UTF8String];
    remove(stdoutPath);
    if(DebuggerAttached()) {
        printf("Hi there Xcode, thank you for debugging me!\n\n");
        int debugserver_pid = getppid();
        printf("Debug server process id: %d group process id: %d\n", (debugserver_pid != 1) ? debugserver_pid : -1, getpgid(getpid()));
        debuggerAttached = true;
    } else {
        redirectOutputs();
    }
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
