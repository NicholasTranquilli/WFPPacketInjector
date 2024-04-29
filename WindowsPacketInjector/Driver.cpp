/*/
/*  ** Driver.cpp **
/*	AUTHOR: Nicholas Tranquilli
/*
/*	DESCRIPTION:
/*	Contains Driver Entrypoint and essential function callback definitions such as DriverUnload.
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

//////////////
// INCLUDES //
//////////////

#include "Driver.h"
#include "InjectionCallout.h"

#pragma warning(disable: 4390)

/////////////
// GLOBALS //
/////////////

// Driver and Device names
#define DRIVER_NAME "LbDriver"
#define DEVICE_NAME L"\\Device\\LbDriver"
#define DOS_DEVICE_NAME L"\\DosDevices\\LbDriver"

// Global handle to the WFP Base Filter Engine
HANDLE lbFilterEngineHandle = NULL;

// Filter and Callout ID's
UINT64 lbInjectionFilterId = 0;
UINT32 lbInjectionCalloutId;

// Callout and Filter names

// Data and constants for the example Callout
#define INJECTION_CALLOUT_NAME		L"InjectionCallout"
// Data and constants for the example Sublayer
#define INJECTION_SUBLAYER_NAME		L"InjectionSublayer"
// Data and constants for the example Filter
#define INJECTION_FILTER_NAME		L"InjectionFilter"

// GUID's (generated with uuidgen.exe in command prompt)
DEFINE_GUID(INJECTION_CALLOUT_GUID,		// cbcf44f8-369a-466d-acec-8a46b29c90d3
	0xcbcf44f8, 0x369a, 0x466d, 0xac, 0xec, 0x8a, 0x46, 0xb2, 0x9c, 0x90, 0xd3);
DEFINE_GUID(INJECTION_SUBLAYER_GUID,	// 1497aadc-9239-49a1-8569-55603592b3d9
	0x1497aadc, 0x9239, 0x49a1, 0x85, 0x69, 0x55, 0x60, 0x35, 0x92, 0xb3, 0xd9);

////////////////////////
// DRIVER ENTRY POINT //
////////////////////////

EXTERN_C
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	WDFDRIVER driver = { 0 };
	WDFDEVICE device = { 0 };
	DEVICE_OBJECT* wdmDevObj = NULL;
	FWPM_SESSION filterSession = { 0 };
	BOOLEAN bInTransaction = FALSE;
	BOOLEAN bCalloutRegistered = FALSE;

	// Initialize WDF driver object
	status = LbInitializeDriver(DriverObject, RegistryPath, &driver, &device);
	if (!NT_SUCCESS(status)) goto Exit;

	// Begin transaction
	filterSession.flags = FWPM_SESSION_FLAG_DYNAMIC;	// Automatically destroys all filters and callouts after this wdf_session ends
	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &filterSession, &lbFilterEngineHandle);
	if (!NT_SUCCESS(status)) goto Exit;
	status = FwpmTransactionBegin(lbFilterEngineHandle, 0);
	if (!NT_SUCCESS(status)) goto Exit;
	bInTransaction = TRUE;

	// Register callout
	wdmDevObj = WdfDeviceWdmGetDeviceObject(device);
	status = RegisterInjectionCallout(wdmDevObj);
	if (!NT_SUCCESS(status)) goto Exit;
	bCalloutRegistered = TRUE;

	// Register sublayer
	status = InitSublayer();
	if (!NT_SUCCESS(status)) goto Exit;

	// Register filter
	status = InitFilter();
	if (!NT_SUCCESS(status)) goto Exit;

	// Finalize transaction
	status = FwpmTransactionCommit(lbFilterEngineHandle);
	if (!NT_SUCCESS(status)) goto Exit;
	bInTransaction = FALSE;

	// Define this driver's unload function
	DriverObject->DriverUnload = DriverUnload;

	// Cleanup and handle any errors
Exit:
	if (!NT_SUCCESS(status)) 
	{
		LBPRINTLN("DRIVER INITIALIZATION FAILED, STATUS CODE 0x%08x", status);
		if (bInTransaction == TRUE) 
		{
			DWORD result = FwpmTransactionAbort(lbFilterEngineHandle);
			if (result == 0) _Analysis_assume_lock_not_held_(lbFilterEngineHandle);
		}
		if (bCalloutRegistered == TRUE)
			FwpsCalloutUnregisterById(lbInjectionCalloutId);
		
		status = STATUS_FAILED_DRIVER_ENTRY;
	}

	return status;
}

/////////////////////////
// DRIVER UNLOAD FUNCS //
/////////////////////////

void DriverUnload(_In_ struct _DRIVER_OBJECT* DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

	NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING symlink = { 0 };

	// Cleanup filters
	status = FwpmFilterDeleteById(lbFilterEngineHandle, lbInjectionFilterId);
	if (!NT_SUCCESS(status)) LBPRINTLN("Failed to unregister filters, STATUS CODE: %d", status);
	status = FwpsCalloutUnregisterById(lbInjectionCalloutId);
	if (!NT_SUCCESS(status)) LBPRINTLN("Failed to unregister callout, STATUS CODE: %d", status);
	
	// Close handle to the WFP Filter Engine
	if (lbFilterEngineHandle) 
	{
		FwpmEngineClose(lbFilterEngineHandle);
		lbFilterEngineHandle = NULL;
	}

	// Cleanup driver
    RtlInitUnicodeString(&symlink, DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&symlink);

    LBPRINTLN("DRIVER UNLOADED");
}

void WDFUnload(_In_ WDFDRIVER Driver)
{
	// Function required for WDF Drivers.
	// In our case, we do not use it.
	// Cleanup is done in DriverUnload function.
    UNREFERENCED_PARAMETER(Driver);
}

/////////////////////////
// INITIALIZE FUNCTION //
/////////////////////////

NTSTATUS LbInitializeDriver(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath, _In_ WDFDRIVER* WdfDriver, _In_ WDFDEVICE* WdfDevice)
{
	NTSTATUS status = STATUS_SUCCESS;
	WDF_DRIVER_CONFIG config = { 0 };
	UNICODE_STRING device_name = { 0 };
	UNICODE_STRING device_symlink = { 0 };
	PWDFDEVICE_INIT device_init = NULL;

	RtlInitUnicodeString(&device_name, DEVICE_NAME);
	RtlInitUnicodeString(&device_symlink, DOS_DEVICE_NAME);

	// Create a WDFDRIVER for this driver
	WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
	config.DriverInitFlags = WdfDriverInitNonPnpDriver;
	config.EvtDriverUnload = WDFUnload; // <-- Necessary for this driver to unload correctly
	status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WdfDriver);
	if (!NT_SUCCESS(status)) goto Exit;

	// Create a WDFDEVICE for this driver
	device_init = WdfControlDeviceInitAllocate(*WdfDriver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);	// only admins and kernel can access device
	if (!device_init) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	// Configure the WDFDEVICE_INIT with a name to allow for access from user mode
	WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_NETWORK);
	WdfDeviceInitSetCharacteristics(device_init, FILE_DEVICE_SECURE_OPEN, FALSE);
	WdfDeviceInitAssignName(device_init, &device_name);
	WdfPdoInitAssignRawDevice(device_init, &GUID_DEVCLASS_NET);
	WdfDeviceInitSetDeviceClass(device_init, &GUID_DEVCLASS_NET);

	status = WdfDeviceCreate(&device_init, WDF_NO_OBJECT_ATTRIBUTES, WdfDevice);
	if (!NT_SUCCESS(status)) {
		WdfDeviceInitFree(device_init);
		goto Exit;
	}

	WdfControlFinishInitializing(*WdfDevice);

Exit:
	return status;
}

/////////////////////////////////////
// HELPER INITIALIZATION FUNCTIONS //
/////////////////////////////////////

NTSTATUS RegisterInjectionCallout(DEVICE_OBJECT* wdm_device)
{
	NTSTATUS status = STATUS_SUCCESS;
	// Run-time Callout Filtering Layer Identifiers Struct
	FWPS_CALLOUT callout = { 0 };
	// Management Filtering Layer Identifiers Struct
	FWPM_CALLOUT calloutManager = { 0 };
	// Display data struct for FWPM
	FWPM_DISPLAY_DATA displayData = { 0 };

	// Check for NULL handle
	if (lbFilterEngineHandle == NULL)
		return STATUS_INVALID_HANDLE;

	// Set callout name
	displayData.name = (wchar_t*)INJECTION_CALLOUT_NAME;

	// Register new Callout with Filtering Engine
	callout.calloutKey = INJECTION_CALLOUT_GUID;
	callout.classifyFn = LbClassifyInject;	// INJECTION FUNCTION
	callout.notifyFn = LbNotify;	// Placeholder function
	callout.flowDeleteFn = LbFlowDelete;	// Placeholder function
	status = FwpsCalloutRegister((void*)wdm_device, &callout, &lbInjectionCalloutId);
	if (!NT_SUCCESS(status)) goto Exit;

	// Add Callout to the system
	calloutManager.calloutKey = INJECTION_CALLOUT_GUID;
	calloutManager.displayData = displayData;
	calloutManager.applicableLayer = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
	calloutManager.flags = 0;
	status = FwpmCalloutAdd(lbFilterEngineHandle, &calloutManager, NULL, NULL);
	if (!NT_SUCCESS(status)) goto Exit;

	LBPRINTLN("REGISTER CALLOUT SUCCESSFUL");

Exit:
	if (!NT_SUCCESS(status)) LBPRINTLN("CALLOUT REGISTRATION FAILED, STATUS CODE: 0x%08x", status);

	return status;
}

NTSTATUS InitSublayer()
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPM_SUBLAYER sublayer = { 0 };

	sublayer.subLayerKey = INJECTION_SUBLAYER_GUID;
	sublayer.displayData.name = (wchar_t*)INJECTION_SUBLAYER_NAME;
	sublayer.flags = 0;
	sublayer.weight = 0x0f;
	status = FwpmSubLayerAdd(lbFilterEngineHandle, &sublayer, NULL);
	if (!NT_SUCCESS(status)) {
		LBPRINTLN("Failed to register example sublayer, status 0x%08x", status);
	}
	else {
		LBPRINTLN("Example sublayer registered");
	}
	return status;
}

NTSTATUS InitFilter()
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPM_FILTER filter = { 0 };


	filter.displayData.name = (wchar_t*)INJECTION_FILTER_NAME;
	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;	// Says this filter's callout MUST make a block/permit decission
	filter.subLayerKey = INJECTION_SUBLAYER_GUID;
	filter.weight.type = FWP_UINT8;
	filter.weight.uint8 = 0xf;		// The weight of this filter within its sublayer
	filter.numFilterConditions = 0;	// If you specify 0, this filter invokes its callout for all traffic in its layer
	filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;	// This layer must match the layer that ExampleCallout is registered to
	filter.action.calloutKey = INJECTION_CALLOUT_GUID;
	status = FwpmFilterAdd(lbFilterEngineHandle, &filter, NULL, &(lbInjectionFilterId));
	if (status != STATUS_SUCCESS) {
		LBPRINTLN("Failed to register example filter, status 0x%08x", status);
	}
	else {
		LBPRINTLN("Example filter registered");
	}

	return status;
}