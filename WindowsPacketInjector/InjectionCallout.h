/*/
/*  ** InjectionCallout.h **
/*	AUTHOR: Nicholas Tranquilli
/*
/*	DESCRIPTION:
/*	Contains forward declerations for custom classifyFn, notifyFn, and flowDeleteFn callbacks.
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

#include "Driver.h"

// Custom classifyFn callout
// Controls packet flow and injection
void LbClassifyInject(
	const FWPS_INCOMING_VALUES* inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	void* layerData,
	const void* classifyContext,
	const FWPS_FILTER* filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT* classifyOut
);

// Custom notifyFn callout
// Does nothing in this implementation
NTSTATUS LbNotify(
	FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	const GUID* filterKey,
	FWPS_FILTER* filter
);

// Custom flowDeleteFn callout
// Does nothing in this implementation
void LbFlowDelete(
	UINT16 layerId,
	UINT32 calloutId,
	UINT64 flowContext
);
