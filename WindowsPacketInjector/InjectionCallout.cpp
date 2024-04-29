/*/
/*  ** InjectionCallout.cpp **
/*	AUTHOR: Nicholas Tranquilli
/*
/*	DESCRIPTION:
/*	Contains function definitions for custom classifyFn, notifyFn, and flowDeleteFn callbacks.
/*	Also contains some helper functions and callbacks only used within this file.
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

#include "InjectionCallout.h"
#include <ntstrsafe.h>

/////////////////////////////
// DEBUG ADDRESS FORMATTER //
/////////////////////////////

#define FORMAT_ADDR(x) (x>>24)&0xFF, (x>>16)&0xFF, (x>>8)&0xFF, x&0xFF

/////////////////////////
// DEBUG PRINT PAYLOAD //
/////////////////////////

void PrintPayload(NET_BUFFER_LIST* netBufferList)
{
	// initial vars
	NET_BUFFER_LIST* currentNBL = netBufferList;
	NET_BUFFER* currentNB = netBufferList->FirstNetBuffer;
	PMDL currentMDL = currentNB->CurrentMdl;
	char* buffer;

	// loop through all NBL's
	while (currentNBL != NULL)
	{
		// loop through all NB's per NBL
		while (currentNB != NULL)
		{
			// loop through all MDL's per NB
			while (currentMDL != NULL)
			{
				// Allocate buffer to get data stored in current MDL
				buffer = (PCHAR)MmGetSystemAddressForMdlSafe(currentMDL, NormalPagePriority | MdlMappingNoExecute);

				LBPRINTLN("COUNT: %d | OFFSET: %d", currentMDL->ByteCount, currentMDL->ByteOffset);

				// if null buffer, skip
				if (!buffer)
				{
					LBPRINT_NO_INFO("EMPTY BUFFER\n");
				}
				else
				{
					for (int i = 0; i < (int)currentMDL->ByteCount; i++)
					{
						char val = buffer[i];

						// print bytes as hex
						LBPRINT_NO_INFO("0x%X ", val);
						// print bytes as char
						//LBPRINT_NO_INFO("%c ", val);
					}
				}

				// new line for new MDL
				LBPRINT_NO_INFO("\n");

				// Next list element
				currentMDL = currentMDL->Next;
			}

			// Next list element
			currentNB = currentNB->Next;
		}

		// Next list element
		currentNBL = NET_BUFFER_LIST_NEXT_NBL(currentNBL);
	}
}

/////////////////////////////
// CUSTOM USERDATA STRUCTS //
/////////////////////////////

struct LB_MATCH_AND_REPLACE
{
	char* match;
	char* replace;
};

struct LB_USERDATA
{
	int count;
	bool enableReversal = false;
	LB_MATCH_AND_REPLACE* strArray;
};

////////////////////////
// INJECTION CALLBACK //
////////////////////////

void LbReplaceCallback(char* packetStr, void* value)
{
	// Cast user value void* to LB_USERDATA struct
	LB_USERDATA* ud = (LB_USERDATA*)value;

	// Result memory pool
	char* result = (char*)ExAllocatePool2(POOL_FLAG_NON_PAGED, 255, 'LBP1');

	// "Zero Out" the new memory
	for (int i = 0; i < 255; i++)
		result[i] = '\0';

	// Save the original position of the result pointer
	char* resOrigin = result;

	// Loop through all characters in packetStr
	for (int i = 0, offset = 0; i < strnlen(packetStr, 255); i++, offset++)
	{
		// Place current char into result
		result[offset] = packetStr[i];

		// Check result against 'match' and 'replace' strings to see if replacement must be done
		for (int k = 0; k < ud->count; k++)
		{
			// Initialize match and replace vars with info from LB_USERDATA struct
			char* match = ud->strArray[k].match;
			char* replace = ud->strArray[k].replace;

			// Check if current string contains 'match'
			char* loc = strstr(result, match);

			if (loc)
			{
				// If successful, swap with the 'replace' str
				strcpy(loc, replace);
				// Increment result pointer by distance offset and reset the offset
				result += offset;
				offset = 0;
				// Break out of inner loop on success
				break;
			}
			else if (!loc)
			{
				// If no result containing 'match' was found, try the inverse 
				loc = strstr(result, replace);

				if (loc)
				{
					// If successful then replace with 'match' string
					strcpy(loc, match);
					// Increment result pointer by distance offset and reset the offset
					result += offset;
					offset = 0;
					// Break out of inner loop on success
					break;
				}
			}
		}
	}

	// DBG print packetStr before copy
	LBPRINTLN("BEFORE COPY:\t%s", packetStr);

	// Copy result to packetStr
	strcpy(packetStr, resOrigin);
	
	// DBG print packetStr after copy
	LBPRINTLN("AFTER COPY:\t%s", packetStr);

	// Free pooled memory in result
	ExFreePool2(resOrigin, 'LBP1', NULL, NULL);
}

//////////////////////////////////
// PACKET PARSING WITH CALLBACK //
//////////////////////////////////

typedef void(LbPacketParseCallback)(char* packetStr, void* value);

void ParsePacket(NET_BUFFER_LIST* netBufferList, LbPacketParseCallback* callbackFn, void* userdata)
{
	// initial vars
	NET_BUFFER_LIST* currentNBL = netBufferList;
	NET_BUFFER* currentNB = netBufferList->FirstNetBuffer;
	PMDL currentMDL = currentNB->CurrentMdl;
	char* buffer;

	// loop through all NBL's
	while (currentNBL != NULL)
	{
		// loop through all NB's per NBL
		while (currentNB != NULL)
		{
			// loop through all MDL's per NB
			while (currentMDL != NULL)
			{
				buffer = (PCHAR)MmGetSystemAddressForMdlSafe(currentMDL, NormalPagePriority | MdlMappingNoExecute);

				// Call user callback here
				callbackFn(buffer, userdata);

				// Next list element
				currentMDL = currentMDL->Next;
			}

			// Next list element
			currentNB = currentNB->Next;
		}

		// Next list element
		currentNBL = NET_BUFFER_LIST_NEXT_NBL(currentNBL);
	}
}

/////////////////////////////////
// INJECTION CLASSIFY FUNCTION //
/////////////////////////////////

void LbClassifyInject(
	const FWPS_INCOMING_VALUES* inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	void* layerData,
	const void* classifyContext,
	const FWPS_FILTER* filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT* classifyOut)
{
	// Initialize some basic packet location and destination information
	UINT32 local_address = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
	UINT32 remote_address = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
	UINT16 local_port = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
	UINT16 remote_port = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;

	UNREFERENCED_PARAMETER(inMetaValues);
	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(filter);

	UNREFERENCED_PARAMETER(remote_address);
	UNREFERENCED_PARAMETER(local_port);
	UNREFERENCED_PARAMETER(local_address);

	// port 80 is HTTP traffic (No Encryption)
	// port 443 is HTTPS (Encrypted)
	// port 53 is DNS

	// Block HTTPS traffic
	if (remote_port == 443)
	{
		static bool first = false;

		if (!first)
		{
			LBPRINTLN("FIRST HTTPS PACKET DETECTED!");
			LBPRINTLN("BLOCKING ALL HTTPS TRAFFIC...");
			first = true;
		}

		classifyOut->actionType = FWP_ACTION_BLOCK;
		return;
	}

	// Check if destination port is the correct port
	if (remote_port == 27015)
	{
		// This is the packet structure for windows
		NET_BUFFER_LIST* buff = (NET_BUFFER_LIST*)layerData;
		
		// If packet data is not null
		if (buff != nullptr)
		{
			LBPRINTLN("PACKET DATA:\n");

			LB_USERDATA ud;
			ud.count = 3; // Number of elements that will be in strArray
			ud.enableReversal = true; // Allow inversion of strings EX: {"Love", "Hate"} results in "Love"  -> "Hate" and "Hate" -> "Love"
			ud.strArray = (LB_MATCH_AND_REPLACE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(LB_MATCH_AND_REPLACE) * ud.count, 'LBP0'); // Create memory pool for string array to allocate space
			
			// Initialize match and replace mappings 
			ud.strArray[0] = { (char*)"Love", (char*)"Hate" };
			ud.strArray[1] = { (char*)"Alice", (char*)"Trudy" };
			ud.strArray[2] = { (char*)"Rob", (char*)"Bob" };

			// Call parse packet and alter with callback function
			ParsePacket(buff, LbReplaceCallback, &ud);

			// Free memory pool
			ExFreePool2(ud.strArray, 'LBP0', NULL, NULL);

			LBPRINT_NO_INFO("\n");
		}
		// Print some debug text
		LBPRINTLN("PERMITTING PACKET...");
	}

	// Allow all other packets
	classifyOut->actionType = FWP_ACTION_PERMIT;
	return;
}

//////////////////////
// UNUSED CALLBACKS //
//////////////////////

NTSTATUS LbNotify(FWPS_CALLOUT_NOTIFY_TYPE notifyType, const GUID* filterKey,FWPS_FILTER* filter)
{
	// Required for WFP driver, function is unused
	
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);
	return STATUS_SUCCESS;
}

void LbFlowDelete(UINT16 layerId, UINT32 calloutId, UINT64 flowContext)
{
	// Required for WFP driver, function is unused

	UNREFERENCED_PARAMETER(layerId);
	UNREFERENCED_PARAMETER(calloutId);
	UNREFERENCED_PARAMETER(flowContext);
}