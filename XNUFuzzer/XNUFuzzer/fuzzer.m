//
//  fuzzer.c
//  XNUFuzzer
//
//  Created by Sem Voigtländer on 5/19/18.
//  Copyright © 2018 Sem Voigtländer. All rights reserved.
//

#include "fuzzer.h"
#include "utils.h"
#include "kextdumper.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>

#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>

#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/spawn.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <sys/time.h>


#include <mach/mach.h>
#include <mach/vm_attributes.h>
#include <mach/vm_task.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach_debug/hash_info.h>
#include <mach_debug/page_info.h>
#include <mach_debug/mach_debug.h>
#include <mach_debug/mach_debug_types.h>
#include <mach/thread_status.h>

#include <pthread.h>
#include <zlib.h>
#include <xpc/xpc.h>

#include <IOKit/IOKitLib.h>
#include <libkern/OSAtomic.h>
#include <libkern/OSByteOrder.h>
#include <libkern/OSAtomicQueue.h>
#include <libkern/OSCacheControl.h>

#include <machine/limits.h>
#include <malloc/malloc.h>

void handler(int signal);

int IOKIT_SERVICE_CNT = 274;
int IOSERVICE_MAX_SELECTORS = 0x4000;
NSArray* iokit_services;
NSMutableDictionary* selectors = NULL;
NSMutableArray* iokit_found_services = NULL;

int iokit_fuzzer_find_services() {
    iokit_services = @[
      @"AGXFirmwareKextG5P",
      @"AGXG5P",
      @"AGXShared",
      @"APFS",
      @"AppleA7IOP",
      @"AppleAE2Audio",
      @"AppleARM64ErrorHandler",
      @"AppleARMIIC",
      @"AppleARMIICDevice",
      @"AppleARMIISAudio",
      @"AppleARMPlatform",
      @"AppleARMPMUCharger",
      @"AppleAuthCP",
      @"AppleAVE",
      @"AppleAVEH8",
      @"AppleBaseband",
      @"AppleBasebandN71",
      @"AppleBasebandPCI",
      @"AppleBasebandPCIMAVControl",
      @"AppleBasebandPCIMAVPDP",
      @"AppleBCMWLAN",
      @"AppleBCMWLanBusInterfacePCIe",
      @"AppleBCMWLANCore",
      @"AppleBCMWLANFirmware_Hashstore",
      @"AppleBiometricSensor",
      @"AppleBiometricServices",
      @"AppleBluetooth",
      @"AppleBluetoothDebugService",
      @"AppleBSDKextStarter",
      @"AppleC26Charger",
      @"AppleChestnutDisplayPMU",
      @"AppleCLCD",
      @"AppleH1CLCD",
      @"AppleM2CLCD",
      @"AppleCredentialManager",
      @"AppleCS35L19Amp",
      @"AppleCS42L71Audio",
      @"AppleCSEmbeddedAudio",
      @"AppleCT700",
      @"AppleD2255PMU",
      @"AppleD5500",
      @"AppleDiagnosticDataAccessReadOnly",
      @"AppleDialogPMU",
      @"AppleEffaceableStorage",
      @"AppleEffaceableBlockDevice",
      @"AppleEmbeddedAudio",
      @"AppleEmbeddedLightSensor",
      @"AppleEmbeddedMikeyBus",
      @"AppleEmbeddedPCIE",
      @"AppleEmbeddedTempSensor",
      @"AppleEmbeddedUSB",
      @"AppleEmbeddedUSBHost",
      @"AppleFirmwareUpdateKext",
      @"AppleFSCompression",
      @"AppleH2CamIn",
      @"AppleH3CamIn",
      @"AppleH4CamIn",
      @"AppleH6CameraInterface",
      @"AppleH6CamIn",
      @"AppleH8ADBE0",
      @"AppleHDQGasGaugeControl",
      @"AppleHIDKeyboard",
      @"AppleIDAMInterface",
      @"AppleIPAppender",
      @"AppleJPEGDriver",
      @"AppleKeyStore",
      @"AppleLMBacklight",
      @"AppleM2ScalerCSC",
      @"AppleM68Buttons",
      @"AppleMesaSEPDriver",
      @"AppleMikeyBusAudio",
      @"AppleMobileApNonce",
      @"AppleMobileFileIntegrity",
      @"AppleMultitouchSPI",
      @"AppleNANDConfigAccess",
      @"AppleNANDFTL",
      @"AppleNVMeSMART",
      @"AppleOnboardSerial",
      @"AppleOnboardSerialSync",
      @"AppleOscar",
      @"AppleOscarCMA",
      @"ApplePinotLCD",
      @"ApplePMGR",
      @"ApplePMGRTemp",
      @"ApplePMP",
      @"AppleS5L8920XPWM",
      @"AppleS5L8940XI2C",
      @"AppleS5L8960XDART",
      @"AppleS5L8960XGPIOIC",
      @"AppleS5L8960XGPIOICFunction",
      @"AppleS5L8960XNCO",
      @"AppleS5L8960XUSB",
      @"AppleS5L8960XWatchDogTimer",
      @"AppleS7002SPU",
      @"AppleS7002SPUSphere",
      @"AppleSPUSphereFunction",
      @"AppleS8000",
      @"AppleS8000AES",
      @"AppleS8000CLPC",
      @"AppleS8000DWI",
      @"AppleS8000PCIe",
      @"AppleS8000PMPFirmware",
      @"AppleS8000SmartIO",
      @"AppleS8003PCIe",
      @"AppleS8003xPCIe",
      @"AppleSamsungPKE",
      @"AppleSamsungSerial",
      @"AppleSamsungSPI",
      @"AppleSEP",
      @"AppleSEPKeyStore",
      @"AppleSEPManager",
      @"AppleSmartIO",
      @"AppleSMC_Embedded",
      @"AppleSN2400Charger",
      @"AppleSPU",
      @"AppleSPUHIDDevice",
      @"AppleSPUHIDDriver",
      @"AppleSPUProfileDriver",
      @"AppleSRSDriver",
      @"AppleSSE",
      @"AppleStockholmControl",
      @"AppleSynopsysOTG2",
      @"AppleSynopsysOTGDevice",
      @"AppleT700XTempSensor",
      @"AppleTemperatureSensor",
      @"AppleTempSensor",
      @"AppleThunderboltIPPort",
      @"AppleTriStar",
      @"AppleUSBAudio",
      @"AppleUSBCardReader",
      @"AppleUSBCommon",
      @"AppleUSBDeviceAudioController",
      @"AppleUSBDeviceMux",
      @"AppleUSBDeviceNCM",
      @"AppleUSBEHCI",
      @"AppleUSBEthernetDevice",
      @"AppleUSBEthernetHost",
      @"AppleUSBHost",
      @"AppleUSBHostCompositeDevice",
      @"AppleUSBHostDevice",
      @"AppleUSBHostInterface",
      @"AppleUSBHostMergeProperties",
      @"AppleUSBHostPacketFilter",
      @"AppleUSBHostT7000",
      @"AppleUSBHSIC",
      @"AppleUSBHub",
      @"AppleUSBMike",
      @"AppleUSBOHCI",
      @"AppleVXD375",
      @"AppleVXD390",
      @"AppleVXD393",
      @"AppleVXE380",
      @"ASIX",
      @"ASP",
      @"AUC",
      @"CDC",
      @"CoreCapture",
      @"CoreCrypto",
      @"DiskImages",
      @"ECM",
      @"EffacingMediaFilter",
      @"EncryptedBlockStorage",
      @"EncryptedMediaFilter",
      @"FairPlayIOKit",
      @"FileBackingStore",
      @"H3H264VideoEncoderDriver",
      @"HFS",
      @"IO80211Family",
      @"IOAcceleratorFamily",
      @"IOAccelMemoryInfo",
      @"IOAccelRestart",
      @"IOAccelShared",
      @"IOAccessoryEAInterface",
      @"IOAccessoryIDBus",
      @"IOAccessoryManager",
      @"IOAccessoryPort",
      @"IOAESAccelerator",
      @"IOAudio2Device",
      @"IOAudio2Family",
      @"IOAudio2Transformer",
      @"IOAudio2TransformerStream",
      @"IOAudioCodecs",
      @"IOAVAudioInterface",
      @"IOAVCECControlInterface",
      @"IOAVController",
      @"IOAVDevice",
      @"IOAVFamily",
      @"IOAVInterface",
      @"IOAVService",
      @"IOAVVideoInterface",
      @"IOBorealisOwl",
      @"IOBufferMemoryDescriptor",
      @"IOCEC",
      @"IOCommand",
      @"IOCommandGate",
      @"IOCommandPool",
      @"IOConditionLock",
      @"IOCoreSurfaceRoot",
      @"IOCPU",
      @"IOCryptoAcceleratorFamily",
      @"IODARTFamily",
      @"IODPAudioInterface",
      @"IODPDevice",
      @"IODPDisplayInterface",
      @"IODPService",
      @"IOEthernetController",
      @"IOFilterInterruptEventSource",
      @"IOFlashController",
      @"IOgPTPPlugin",
      @"IOHDCPFamily",
      @"IOHDIXController",
      @"IOHIDEventService",
      @"IOHIDFamily",
      @"IOHIDLib",
      @"IOHIDResourceDevice",
      @"IOHistogramReporter",
      @"IOMikeyBusBulkPipe",
      @"IOMikeyBusDevice",
      @"IOMikeyBusFunctionGroup",
      @"IOMobileFramebuffer",
      @"IOMobileGraphicsFamily",
      @"IONetwork",
      @"IONetworkingFamily",
      @"IONetworkStack",
      @"IONetworkStackUserClient",
      @"IONVMeFamily",
      @"IONVRAMController",
      @"IOPCIFamily",
      @"IOPKEAccelerator",
      @"IOPlatformDevice",
      @"IOPlatformExpert",
      @"IOPlatformExpertDevice",
      @"IOPMinformee",
      @"IOPMPowerSource",
      @"IOPMrootDomain",
      @"IOPolledInterface",
      @"IOPowerConnection",
      @"IOPrintPlane",
      @"IOPRNGAccelerator",
      @"IOSCSIArchitectureModelFamily",
      @"IOSCSIBlockCommandsDevice",
      @"IOSerialFamily",
      @"IOSHA1Accelerator",
      @"IOSimpleReporter",
      @"IOSkyWalkFamily",
      @"IOSlowAdaptiveClockingFamily",
      @"IOStateReporter",
      @"IOStream",
      @"IOStreamAudio",
      @"IOSurface",
      @"IOSurfaceRoot",
      @"IOTextEncryptionFamily",
      @"IOTimerEventSource",
      @"IOTimeSyncFamily",
      @"IOTimeSyncClockManager",
      @"IOUSBDeviceFamily",
      @"IOUSBDeviceInterface",
      @"IOUSBDeviceLib",
      @"IOUSBHostHIDDevice",
      @"IOUSBMassStorageDriver",
      @"IOUserClient",
      @"IOUserEthernet",
      @"IOUserEthernetResource",
      @"IOWatchDogTimer",
      @"KDIDiskImageNub",
      @"KernelBacked",
      @"LightWeightVolumeManager",
      @"LSKDIOKit",
      @"LSKDIOKitMSE",
      @"mDNSOffload",
      @"RAMBackingStore",
      @"UDIFDiskImage",
      @"wlDNSOffload"];
    printf("Looking for sandbox-container accessible services: \n");
    iokit_found_services = [[NSMutableArray alloc] init];
    io_master_t master = kIOMasterPortDefault;
    io_iterator_t it = MACH_PORT_NULL;
    io_service_t service = MACH_PORT_NULL;
    for(NSString* iokit_service in iokit_services) {
        io_connect_t conn = MACH_PORT_NULL;
        if(IOServiceOpen(IOServiceGetMatchingService(master, IOServiceMatching(iokit_service.UTF8String)), mach_task_self(), 0, &conn) == KERN_SUCCESS && conn != MACH_PORT_NULL && ![iokit_found_services containsObject:iokit_service]) {
            [iokit_found_services addObject:iokit_service];
            conn = MACH_PORT_NULL;
            printf("Found %s\n", iokit_service.UTF8String);
        }
        IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching([iokit_service UTF8String]), &it);
        for(int i = 0; i < 1000; i++) {
            service = IOIteratorNext(it);
            char foundName[0x1000];
            memset(&foundName, 0, sizeof(foundName));
            IORegistryEntryGetName(service, (char*)&foundName);
            if(IO_OBJECT_NULL != service && IOServiceOpen(service, mach_task_self(), 0, &conn) == KERN_SUCCESS && conn != MACH_PORT_NULL && ![iokit_found_services containsObject:[NSString stringWithUTF8String:foundName]]) {
                [iokit_found_services addObject:[NSString stringWithUTF8String:foundName]];
                printf("Found %s using iteration\n", foundName);
            }
        }
    }
    printf("\n");
    return 0;
}

int iokit_fuzzer_find_selectors() {
    
    if(iokit_found_services.count <= 0) {
        printf("Please give me some services to find selectors for.\n");
    }
    
    printf("Finding selectors for %d services...\n", (int)iokit_found_services.count);
    selectors = [[NSMutableDictionary alloc] init];
    for(NSString* iokit_service in iokit_found_services) {
        
        kern_return_t err = KERN_SUCCESS;
        io_connect_t conn = MACH_PORT_NULL;
        io_iterator_t it = MACH_PORT_NULL;
        io_service_t service = MACH_PORT_NULL;
        
        NSMutableArray* found_selectors = [[NSMutableArray alloc] init];
        //Try to get the service
        service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(iokit_service.UTF8String));
        if(service == MACH_PORT_NULL) {
            printf("Iterating tree to connect to %s... ", iokit_service.UTF8String);
            bool found = false;
            for(NSString* parent in iokit_services) {
                IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching(parent.UTF8String), &it);
                
                for(int i = 0; i < 1000; i++) {
                    service = IOIteratorNext(it);
                    char serviceName[0x1000];
                    memset(&serviceName, 0, sizeof(serviceName));
                    IORegistryEntryGetName(service, (char*)&serviceName);
                    if(strcmp(serviceName, iokit_service.UTF8String) == 0) {
                        printf("Got it!\n");
                        found = true;
                        break;
                    }
                }
                if(found) {
                    break;
                }
                
            }
            if(service == IO_OBJECT_NULL) {
                printf("\nFailed to get service %s, that's odd.\n", iokit_service.UTF8String);
            }
        }
        
        //Try to connect to the service
        err = IOServiceOpen(service, mach_task_self(), 0, &conn);
        
        //Find the selectors
        if(err == KERN_SUCCESS) {
            for(int sel = 0; sel < 0x4000; sel++) {
                err = IOConnectCallMethod(conn, sel, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
                NSMutableDictionary* selector_info = [[NSMutableDictionary alloc] init];
                [selector_info setValue:[NSNumber numberWithInt:sel] forKey:@"sel"];
                [selector_info setValue:[NSNumber numberWithInt:err] forKey:@"info"];
                [found_selectors addObject:selector_info];
                
            }
            [selectors setValue:found_selectors forKey:iokit_service];
        }
    }
    printf("Found valid selectors.\n");
    for(NSString* iokit_service in iokit_found_services) {
        printf("\n%s: \n",iokit_service.UTF8String);
        for(NSDictionary* selector in [selectors valueForKey:iokit_service]) {
            NSString* info = [NSString stringWithUTF8String:mach_error_string([[selector valueForKey:@"info"] intValue])];
            if(![info containsString:@"unsupported"] && ![info containsString:@"invalid"]) {
                printf("selector %d: %s\n",[[selector valueForKey:@"sel"] intValue], info.UTF8String);
            }
            
        }
        
    }
    printf("\n");
    return 0;
}

int iokit_fuzzer_find_input() {
    
    
    io_connect_t conn = MACH_PORT_NULL;
    io_service_t service = MACH_PORT_NULL;
    io_iterator_t it = MACH_PORT_NULL;
    kern_return_t err = KERN_SUCCESS;
    
    
    for(NSString* iokit_service in iokit_found_services) {
        service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(iokit_service.UTF8String));
        if(service == MACH_PORT_NULL) {
            printf("Iterating tree to connect to %s... ", iokit_service.UTF8String);
            bool found = false;
            for(NSString* parent in iokit_services) {
                IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching(parent.UTF8String), &it);
                
                for(int i = 0; i < 1000; i++) {
                    service = IOIteratorNext(it);
                    char serviceName[0x1000];
                    memset(&serviceName, 0, sizeof(serviceName));
                    IORegistryEntryGetName(service, (char*)&serviceName);
                    if(strcmp(serviceName, iokit_service.UTF8String) == 0) {
                        printf("Got it!\n");
                        found = true;
                        break;
                    }
                }
                if(found) {
                    break;
                }
                
            }
            if(service == IO_OBJECT_NULL) {
                printf("\nFailed to get service %s, that's odd.\n", iokit_service.UTF8String);
            }
        }
        
        //Try to connect to the service
        err = IOServiceOpen(service, mach_task_self(), 0, &conn);
        
        for(NSDictionary* selector in [selectors valueForKey:iokit_service]) {
            
            for(int attempt = 0; attempt < 0x1000; attempt++) {
                struct timeval time;
                gettimeofday(&time,NULL);
                srand((int)(time.tv_sec * 1000) + (time.tv_usec / 1000));
                NSString* info = [NSString stringWithUTF8String:mach_error_string([[selector valueForKey:@"info"] intValue])];
                if(![info containsString:@"unsupported"] && ![info containsString:@"invalid"]) {
                    int sel = [[selector valueForKey:@"sel"] intValue];
                    unsigned char in[0x2000];
                    unsigned char out[0x2000];
                    uint64_t inc[100];
                    uint64_t outc[100];
                    size_t out_size = (rand() * (0x2000-8)) + 8;
                    uint32_t outc_size = (rand() * 92) + 8;
                    memset(in, 0, 0x2000);
                    memset(inc, 0, 100*sizeof(uint64_t));
                    int ii = rand()%(0x2000+1)+1;
                    int iic = rand()%(0x100+1)+1;
                    for (int i = 0; i < ii;  i++) in[i] = (rand() % 0xF) + 1;
                    for (int i = 0; i < iic; i++) inc[i] = (rand() % 0xFFFF) + 1;
                    
                    
                    err = IOConnectCallMethod(conn, sel, inc, iic, in, ii, outc, &outc_size, out, &out_size);
                    printf("%s(%d)(scalar): %s. (outc size: %#llx, out size: %#llx)\n", iokit_service.UTF8String, sel, mach_error_string(err), (long long)outc_size, (long long)out_size);
                    hexdump((unsigned char*)out, sizeof(&out));
                   
                }
                
            }
        }
    }
    return 0;
}

int iokit_fuzzer_main() {
    NSString* docsDir = [[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject] stringByAppendingString:@"/"];
    printf("Attempting to disassemble the kernel to get information about the kernel extensions and their classes, selectors and input.\n");
    //kext_dumper(docsDir); //not supported yet
    iokit_fuzzer_find_services();
    iokit_fuzzer_find_selectors();
    iokit_fuzzer_find_input();
    printf("The fuzzer has finished.\n");
    return 0;
}

typedef struct {
    int id;
    char* name;
} syscall_t;

int syscall_fuzzer_main() {
    
    struct sigaction sigact;
    sigact.sa_handler = handler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(SIGINT, &sigact, (struct sigaction *)NULL);
    sigaction(SIGABRT, &sigact, (struct sigaction *)NULL);
    sigaction(SIGALRM, &sigact, (struct sigaction *)NULL);
    sigaction(SIGBUS, &sigact, (struct sigaction *)NULL);
    sigaction(SIGSEGV, &sigact, (struct sigaction *)NULL);
    sigaction(SIGSYS, &sigact, (struct sigaction *)NULL);
    printf("Fuzzing system calls.\n");
    
    int err = -1;
    
    syscall_t syscalls[] =
    {
        SYS_open, "open",
        SYS_close, "close",
        SYS_delete, "delete",
        SYS_rename, "rename",
        SYS_read, "read",
        SYS_write, "write",
        SYS_setgid, "setgid",
        SYS_setpgid, "setpgid",
        SYS_setuid, "setuid",
        SYS_setegid, "setegid",
        SYS_seteuid, "setuid",
        SYS_fork, "fork",
        SYS_thread_selfid, "thread_selfid",
        SYS_proc_info, "proc_info",
        SYS_execve, "execve",
        SYS_proc_uuid_policy, "proc_uuid_policy",
        SYS_sync, "sync",
        SYS_kdebug_typefilter, "kdebug_typefilter",
        SYS_mmap, "mmap",
        SYS_bind, "bind",
        SYS_listen, "listen",
        SYS_recvmsg, "recvmsg",
        SYS_recvmsg_x, "recvmsg_x",
        SYS_posix_spawn, "posix_spawn"
    };

    for(int current = 0; current < sizeof(syscalls) / sizeof(syscall_t); current++) {
        srand(clock());
        printf("fuzzing %s\n",syscalls[current].name);
        for(int attempt = 0; attempt < 100; attempt++) {
            int input = rand() & 0xFF;
            err = syscall(syscalls[current].id, input);
            printf("%s(%d): %d (input: %#x)\n",syscalls[current].name, syscalls[current].id, err, input);
        }
        printf("\n");
    }
    
    return 0;
}

void handler(int signal) {
    printf("We received a signal: %d\n", signal);
}
