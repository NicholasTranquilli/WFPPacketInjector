/*/
/*  ** Driver.h **
/*	AUTHOR: Nicholas Tranquilli
/*
/*	DESCRIPTION:
/*	Contains forward declerations for Driver and Device callbacks.
/*  
/*  SOURCES AND CITATIONS (NAME, PROJECT, URL):
/*		- Microsoft, Windows-Driver-Samples, https://github.com/microsoft/Windows-driver-samples/
/*			* Contains some very useful demos on a variety of different drivers.
/*			* The WFP driver sample featuring packet injection was helpful.
/*      - Jared Wright, WFPStarterKit, https://github.com/JaredWright/WFPStarterKit/blob/master/
/*			* WFPStarterKit by JaredWright is an incredible source for learning about
/*			* Windows Filtering Platform and creating WFP Callout Drivers.
/*
/*	ADDITIONAL NOTES:
/*	This driver and source code is for educational purposes only and was created
/*	as a final project for Central Connecticut State University’s CS 492 course.
/*/

#pragma once

enum _WDF_REQUEST_TYPE : int; // Seems to be required for wdf.h compilation in C++ environment

#define INITGUID	// REQUIRED FOR Devguid.h

#define NDIS61 1    // Seems to be required when compiling for Windows 7 and up

#include <ntddk.h>
#include <wdf.h>

#include <guiddef.h>
#include <initguid.h>
#include <devguid.h>

#pragma warning(push)
#pragma warning(disable: 4201)
#include <fwpsk.h>
#pragma warning(pop)

#include <fwpmk.h>
#include <fwpvi.h>

// MUST ADD FOLLOWING LIBS IN "PROPERTIES->LINKER->INPUT->ADDITIONAL DEPENDENCIES":
//  - $(DDK_LIB_PATH)wdmsec.lib
//  - $(DDK_LIB_PATH)fwpkclnt.lib

#ifndef LBPRINTF
#define LBPRINTF(...) \
    {\
    DbgPrintEx(0, 0, "<%s> ",  __FUNCTION__);\
    DbgPrintEx(0, 0, __VA_ARGS__);\
    }
#endif

#ifndef LBPRINTLN
#define LBPRINTLN(...) \
    {\
    DbgPrintEx(0, 0, "<%s> ",  __FUNCTION__);\
    DbgPrintEx(0, 0, __VA_ARGS__);\
    DbgPrintEx(0, 0, "\n");\
    }
#endif

#ifndef LBPRINT_NO_INFO
#define LBPRINT_NO_INFO(...) \
    DbgPrintEx(0, 0, __VA_ARGS__)
#endif

//////////////////////////
// FORWARD DECLERATIONS //
//////////////////////////

EXTERN_C
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
EVT_WDF_DRIVER_UNLOAD WDFUnload;

NTSTATUS LbInitializeDriver(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath,
    _In_ WDFDRIVER* WdfDriver,
    _In_ WDFDEVICE* WdfDevice
);

// Demonstrates how to register/unregister a callout, sublayer, and filter to the Base Filtering Engine
NTSTATUS RegisterInjectionCallout(DEVICE_OBJECT* wdm_device);
NTSTATUS InitSublayer();
NTSTATUS InitFilter();
