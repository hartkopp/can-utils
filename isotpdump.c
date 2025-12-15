/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause) */
/*
 * isotpdump.c - dump and explain ISO15765-2 protocol CAN frames
 *
 * Copyright (c) 2008 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Volkswagen nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * The provided data structures and external interfaces from this code
 * are not restricted to be used by modules with a GPL compatible license.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Send feedback to <linux-can@vger.kernel.org>
 *
 */

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/can.h>
#include <linux/can/raw.h>
#include <linux/sockios.h>

#include "terminal.h"

#define NO_CAN_ID 0xFFFFFFFFU

/* CAN CC/FD/XL frame union */
union cfu {
	struct can_frame cc;
	struct canfd_frame fd;
	struct canxl_frame xl;
};

const char fc_info [4][9] = { "CTS", "WT", "OVFLW", "reserved" };
const int canfx_on = 1;

void print_usage(char *prg)
{
	fprintf(stderr, "\nUsage: %s [options] <CAN interface>\n", prg);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "         -s <can_id>  (source can_id. Use 8 digits for extended IDs)\n");
	fprintf(stderr, "         -d <can_id>  (destination can_id. Use 8 digits for extended IDs)\n");
	fprintf(stderr, "         -b <can_id>  (broadcast can_id, Use 8 digits for extended IDs)\n");
	fprintf(stderr, "         -x <addr>    (extended addressing mode. Use 'any' for all addresses)\n");
	fprintf(stderr, "         -X <addr>    (extended addressing mode (rx addr). Use 'any' for all)\n");
	fprintf(stderr, "         -c           (color mode)\n");
	fprintf(stderr, "         -a           (print data also in ASCII-chars)\n");
	fprintf(stderr, "         -3           (limit printing of CFs to 3 items per PDU)\n");
	fprintf(stderr, "         -L <length>  (limit the printed data length. Minimum <length> = 8)\n");
	fprintf(stderr, "         -t <type>    (timestamp: (a)bsolute/(d)elta/(z)ero/(A)bsolute w date)\n");
	fprintf(stderr, "         -u           (print uds messages)\n");
	fprintf(stderr, "\nCAN IDs and addresses are given and expected in hexadecimal values.\n");
	fprintf(stderr, "\nUDS output contains a flag which provides information about the type of the \n");
	fprintf(stderr, "message.\n\n");
	fprintf(stderr, "Flags:\n");
	fprintf(stderr, "       [SRQ]  = Service Request\n");
	fprintf(stderr, "       [PSR]  = Positive Service Response\n");
	fprintf(stderr, "       [NRC]  = Negative Response Code\n");
	fprintf(stderr, "       [???]  = Unknown (not specified)\n");
	fprintf(stderr, "\n");
}

void print_uds_message(int service, int nrc)
{
	char *service_name;
	char *flag = "[???]";

	if ((service >= 0x50 && service <= 0x7E) || (service >= 0xC3 && service <= 0xC8)) {
		flag = "[PSR]";
		service = service - 0x40;
	} else if ((service >= 0x10 && service <= 0x3E) ||
		   (service >= 0x83 && service <= 0x88) ||
		   (service >= 0xBA && service <= 0xBE))
		flag = "[SRQ]";
	
	switch(service) {
	case 0x10: service_name = "DiagnosticSessionControl"; break;
	case 0x11: service_name = "ECUReset"; break;
	case 0x14: service_name = "ClearDiagnosticInformation"; break;
	case 0x19: service_name = "ReadDTCInformation"; break;
	case 0x22: service_name = "ReadDataByIdentifier"; break;
	case 0x23: service_name = "ReadMemoryByAddress"; break;
	case 0x24: service_name = "ReadScalingDataByIdentifier"; break;
	case 0x27: service_name = "SecurityAccess"; break;
	case 0x28: service_name = "CommunicationControl"; break;
	case 0x2A: service_name = "ReadDataByPeriodicIdentifier"; break;
	case 0x2C: service_name = "DynamicallyDefineDataIdentifier"; break;
	case 0x2E: service_name = "WriteDataByIdentifier"; break;
	case 0x2F: service_name = "InputOutputControlByIdentifier"; break;
	case 0x31: service_name = "RoutineControl"; break;
	case 0x34: service_name = "RequestDownload"; break;
	case 0x35: service_name = "RequestUpload"; break;
	case 0x36: service_name = "TransferData"; break;
	case 0x37: service_name = "RequestTransferExit"; break;
	case 0x38: service_name = "RequestFileTransfer"; break;
	case 0x3D: service_name = "WriteMemoryByAddress"; break;
	case 0x3E: service_name = "TesterPresent"; break;
	case 0x83: service_name = "AccessTimingParameter"; break;
	case 0x84: service_name = "SecuredDataTransmission"; break;
	case 0x85: service_name = "ControlDTCSetting"; break;
	case 0x86: service_name = "ResponseOnEvent"; break;
	case 0x87: service_name = "LinkControl"; break;
	case 0x7F: flag = "[NRC]";
		switch (nrc) {
		case 0x00: service_name = "positiveResponse"; break;
		case 0x10: service_name = "generalReject"; break;
		case 0x11: service_name = "serviceNotSupported"; break;
		case 0x12: service_name = "sub-functionNotSupported"; break;
		case 0x13: service_name = "incorrectMessageLengthOrInvalidFormat"; break;
		case 0x14: service_name = "responseTooLong"; break;
		case 0x21: service_name = "busyRepeatRequest"; break;
		case 0x22: service_name = "conditionsNotCorrect"; break;
		case 0x24: service_name = "requestSequenceError"; break;
		case 0x25: service_name = "noResponseFromSubnetComponent"; break;
		case 0x26: service_name = "FailurePreventsExecutionOfRequestedAction"; break;
		case 0x31: service_name = "requestOutOfRange"; break;
		case 0x33: service_name = "securityAccessDenied"; break;
		case 0x35: service_name = "invalidKey"; break;
		case 0x36: service_name = "exceedNumberOfAttempts"; break;
		case 0x37: service_name = "requiredTimeDelayNotExpired"; break;
		case 0x70: service_name = "uploadDownloadNotAccepted"; break;
		case 0x71: service_name = "transferDataSuspended"; break;
		case 0x72: service_name = "generalProgrammingFailure"; break;
		case 0x73: service_name = "wrongBlockSequenceCounter"; break;
		case 0x78: service_name = "requestCorrectlyReceived-ResponsePending"; break;
		case 0x7E: service_name = "sub-functionNotSupportedInActiveSession"; break;
		case 0x7F: service_name = "serviceNotSupportedInActiveSession"; break;
		case 0x81: service_name = "rpmTooHigh"; break;
		case 0x82: service_name = "rpmTooLow"; break;
		case 0x83: service_name = "engineIsRunning"; break;
		case 0x84: service_name = "engineIsNotRunning"; break;
		case 0x85: service_name = "engineRunTimeTooLow"; break;
		case 0x86: service_name = "temperatureTooHigh"; break;
		case 0x87: service_name = "temperatureTooLow"; break;
		case 0x88: service_name = "vehicleSpeedTooHigh"; break;
		case 0x89: service_name = "vehicleSpeedTooLow"; break;
		case 0x8A: service_name = "throttle/PedalTooHigh"; break;
		case 0x8B: service_name = "throttle/PedalTooLow"; break;
		case 0x8C: service_name = "transmissionRangeNotInNeutral"; break;
		case 0x8D: service_name = "transmissionRangeNotInGear"; break;
		case 0x8F: service_name = "brakeSwitch(es)NotClosed (Brake Pedal not pressed or not applied)"; break;
		case 0x90: service_name = "shifterLeverNotInPark"; break;
		case 0x91: service_name = "torqueConverterClutchLocked"; break;
		case 0x92: service_name = "voltageTooHigh"; break;
		case 0x93: service_name = "voltageTooLow"; break;

		default:
			if (nrc > 0x37 && nrc < 0x50) {
				service_name = "reservedByExtendedDataLinkSecurityDocument"; break;
			}
			else if (nrc > 0x93 && nrc < 0xF0) {
				service_name = "reservedForSpecificConditionsNotCorrect"; break;
			}
			else if (nrc > 0xEF && nrc < 0xFE) {
				service_name = "vehicleManufacturerSpecificConditionsNotCorrect"; break;
			}
			else {
				service_name = "ISOSAEReserved"; break;
			}
		}
		break;
	default: service_name = "Unknown";
	}
	printf("%s %s", flag, service_name);
}

int main(int argc, char **argv)
{
	int s;
	struct sockaddr_can addr;
	struct can_filter rfilter[3];
	static union cfu cu;
	struct can_raw_vcid_options vcid_opts = {
		.flags = CAN_RAW_XL_VCID_RX_FILTER,
		.rx_vcid = 0,
		.rx_vcid_mask = 0,
	};
	__u8 *data;
	int nbytes, i;
	canid_t src = NO_CAN_ID;
	canid_t dst = NO_CAN_ID;
	canid_t bst = NO_CAN_ID;
	canid_t rx_id;
	int ext = 0;
	int extaddr = 0;
	int extany = 0;
	int rx_ext = 0;
	int rx_extaddr = 0;
	int rx_extany = 0;
	int asc = 0;
	int limit_cfs = 0;
	int src_cfs = 0;
	int dst_cfs = 0;
	int bst_cfs = 0;
	int color = 0;
	int uds_output = 0;
	int uds_data_start = 0;
	int timestamp = 0;
	int datidx = 0;
	unsigned long fflen = 0;
	struct timeval tv, last_tv;
	unsigned int n_pci;
	int framelen;
	int max_printlen = INT_MAX;
	int opt;

	last_tv.tv_sec  = 0;
	last_tv.tv_usec = 0;

	while ((opt = getopt(argc, argv, "s:d:b:a3L:x:X:ct:u?")) != -1) {
		switch (opt) {
		case 's':
			src = strtoul(optarg, NULL, 16);
			if (strlen(optarg) > 7)
				src |= CAN_EFF_FLAG;
			break;

		case 'd':
			dst = strtoul(optarg, NULL, 16);
			if (strlen(optarg) > 7)
				dst |= CAN_EFF_FLAG;
			break;

		case 'b':
			bst = strtoul(optarg, NULL, 16);
			if (strlen(optarg) > 7)
				bst |= CAN_EFF_FLAG;
			break;

		case 'c':
			color = 1;
			break;

		case 'a':
			asc = 1;
			break;

		case '3':
			limit_cfs = 1;
			break;

		case 'x':
			ext = 1;
			if (!strncmp(optarg, "any", 3))
				extany = 1;
			else
				extaddr = strtoul(optarg, NULL, 16) & 0xFF;
			break;

		case 'L':
			max_printlen = atoi(optarg);
			if (max_printlen < 8) {
				fprintf(stderr, "data print limit %d is too low.\n", max_printlen);
				print_usage(basename(argv[0]));
				exit(1);
			}
			break;

		case 'X':
			rx_ext = 1;
			if (!strncmp(optarg, "any", 3))
				rx_extany = 1;
			else
				rx_extaddr = strtoul(optarg, NULL, 16) & 0xFF;
			break;

		case 't':
			timestamp = optarg[0];
			if ((timestamp != 'a') && (timestamp != 'A') &&
			    (timestamp != 'd') && (timestamp != 'z')) {
				printf("%s: unknown timestamp mode '%c' - ignored\n",
				       basename(argv[0]), optarg[0]);
				timestamp = 0;
			}
			break;

		case 'u':
		        uds_output = 1;
			break;

		case '?':
			print_usage(basename(argv[0]));
			exit(0);
			break;

		default:
			fprintf(stderr, "Unknown option %c\n", opt);
			print_usage(basename(argv[0]));
			exit(1);
			break;
		}
	}

	if (rx_ext && !ext) {
		print_usage(basename(argv[0]));
		exit(0);
	}

	if ((argc - optind) != 1 || src == NO_CAN_ID || dst == NO_CAN_ID) {
		print_usage(basename(argv[0]));
		exit(0);
	}

	if ((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		perror("socket");
		return 1;
	}

	/* try to switch the socket into CAN FD mode */
	setsockopt(s, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &canfx_on, sizeof(canfx_on));
	setsockopt(s, SOL_CAN_RAW, CAN_RAW_XL_FRAMES, &canfx_on, sizeof(canfx_on));
	/* try to enable the CAN XL VCID pass through mode */
	setsockopt(s, SOL_CAN_RAW, CAN_RAW_XL_VCID_OPTS, &vcid_opts, sizeof(vcid_opts));


	if (src & CAN_EFF_FLAG) {
		rfilter[0].can_id   = src & (CAN_EFF_MASK | CAN_EFF_FLAG);
		rfilter[0].can_mask = (CAN_EFF_MASK|CAN_EFF_FLAG|CAN_RTR_FLAG);
	} else {
		rfilter[0].can_id   = src & CAN_SFF_MASK;
		rfilter[0].can_mask = (CAN_SFF_MASK|CAN_EFF_FLAG|CAN_RTR_FLAG);
	}

	if (dst & CAN_EFF_FLAG) {
		rfilter[1].can_id   = dst & (CAN_EFF_MASK | CAN_EFF_FLAG);
		rfilter[1].can_mask = (CAN_EFF_MASK|CAN_EFF_FLAG|CAN_RTR_FLAG);
	} else {
		rfilter[1].can_id   = dst & CAN_SFF_MASK;
		rfilter[1].can_mask = (CAN_SFF_MASK|CAN_EFF_FLAG|CAN_RTR_FLAG);
	}

	if (bst & CAN_EFF_FLAG) {
		rfilter[2].can_id   = bst & (CAN_EFF_MASK | CAN_EFF_FLAG);
		rfilter[2].can_mask = (CAN_EFF_MASK|CAN_EFF_FLAG|CAN_RTR_FLAG);
	} else {
		rfilter[2].can_id   = bst & CAN_SFF_MASK;
		rfilter[2].can_mask = (CAN_SFF_MASK|CAN_EFF_FLAG|CAN_RTR_FLAG);
	}

	if (bst != NO_CAN_ID)
		setsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter, sizeof(rfilter));
	else
		setsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter, sizeof(rfilter) - sizeof(rfilter[0]));

	addr.can_family = AF_CAN;
	addr.can_ifindex = if_nametoindex(argv[optind]);
	if (!addr.can_ifindex) {
		perror("if_nametoindex");
		return 1;
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 1;
	}

	while (1) {
		nbytes = read(s, &cu, sizeof(cu));

		if (nbytes < (int)CANXL_HDR_SIZE + CANXL_MIN_DLEN) {
			fprintf(stderr, "read: no CAN frame\n");
			return 1;
		}

		if (cu.xl.flags & CANXL_XLF) {
			if (nbytes != (int)CANXL_HDR_SIZE + cu.xl.len) {
				printf("nbytes = %d\n", nbytes);
				fprintf(stderr, "read: no CAN XL frame\n");
				return 1;
			}
			rx_id = cu.xl.prio & CANXL_PRIO_MASK; /* remove VCID value */
			data = cu.xl.data;
			framelen = cu.xl.len;
		} else {
			/* mark dual-use struct canfd_frame */
			if (nbytes == CAN_MTU)
				cu.fd.flags = 0;
			else if (nbytes == CANFD_MTU)
				cu.fd.flags |= CANFD_FDF;
			else {
				fprintf(stderr, "read: incomplete CAN CC/FD frame\n");
				return 1;
			}
			rx_id = cu.fd.can_id;
			data = cu.fd.data;
			framelen = cu.fd.len;
		}

		if (rx_id == src && ext && !extany &&
		    extaddr != *(data))
			continue;

		if (rx_id == dst && rx_ext && !rx_extany &&
		    rx_extaddr != *(data))
			continue;

		datidx = 0;
		n_pci = *(data + ext);

		/* Consecutive Frame limiter enabled? */
		if (limit_cfs && (n_pci & 0xF0) == 0x20) {
			if (rx_id == src && src_cfs > 2)
				continue;
			if (rx_id == dst && dst_cfs > 2)
				continue;
			if (rx_id == bst && bst_cfs > 2)
				continue;
		}

		if (color) {
			if (rx_id == src)
				printf("%s", FGRED);
			else if (rx_id == dst)
				printf("%s", FGBLUE);
			else if (rx_id == bst)
				printf("%s", FGGREEN);
		}

		if (timestamp) {
			ioctl(s, SIOCGSTAMP, &tv);

			switch (timestamp) {
			case 'a': /* absolute with timestamp */
				printf("(%llu.%06llu) ", (unsigned long long)tv.tv_sec, (unsigned long long)tv.tv_usec);
				break;

			case 'A': /* absolute with date */
			{
				struct tm tm;
				char timestring[25];

				tm = *localtime(&tv.tv_sec);
				strftime(timestring, 24, "%Y-%m-%d %H:%M:%S",
					 &tm);
				printf("(%s.%06llu) ", timestring, (unsigned long long)tv.tv_usec);
			} break;

			case 'd': /* delta */
			case 'z': /* starting with zero */
			{
				struct timeval diff;

				if (last_tv.tv_sec == 0) /* first init */
					last_tv = tv;
				diff.tv_sec = tv.tv_sec - last_tv.tv_sec;
				diff.tv_usec = tv.tv_usec - last_tv.tv_usec;
				if (diff.tv_usec < 0)
					diff.tv_sec--, diff.tv_usec += 1000000;
				if (diff.tv_sec < 0)
					diff.tv_sec = diff.tv_usec = 0;
				printf("(%llu.%06llu) ", (unsigned long long)diff.tv_sec,
				       (unsigned long long)diff.tv_usec);

				if (timestamp == 'd')
					last_tv =
						tv; /* update for delta calculation */
			} break;

			default: /* no timestamp output */
				break;
			}
		}

		if (rx_id & CAN_EFF_FLAG)
			printf(" %s  %8X", argv[optind], rx_id & CAN_EFF_MASK);
		else
			printf(" %s  %3X", argv[optind], rx_id & CAN_SFF_MASK);

		if (ext)
			printf("{%02X}", *(data));

		if (cu.xl.flags & CANXL_XLF)
			printf(" [%04d] ", framelen);
		else if (nbytes == CAN_MTU)
			printf("   [%d]  ", framelen);
		else
			printf("  [%02d]  ", framelen);

		switch (n_pci & 0xF0) {
		case 0x00:
			uds_data_start = 1;

			/* Consecutive Frame limiter enabled? */
			if (limit_cfs) {
				if (rx_id == src)
					src_cfs = 0;
				if (rx_id == dst)
					dst_cfs = 0;
				if (rx_id == bst)
					bst_cfs = 0;
			}

			if ((n_pci & 0xF) && (n_pci <= 7)) {
				printf("[SF] ln: %-4d data:", n_pci);
				datidx = ext + 1;
			} else {
				/* n_pci == 0 (FD extension) or > 8 (XL extension) */
				printf("[SF] ln: %-4d data:",
				       ((n_pci & 0x7) << 8) + *(data + ext + 1));
				datidx = ext + 2;
			}
			break;

		case 0x10:
			uds_data_start = 1;

			/* Consecutive Frame limiter enabled? */
			if (limit_cfs) {
				if (rx_id == src)
					src_cfs = 0;
				if (rx_id == dst)
					dst_cfs = 0;
				if (rx_id == bst)
					bst_cfs = 0;
			}

			fflen = ((n_pci & 0x0F) << 8) + *(data + ext + 1);
			if (fflen)
				datidx = ext + 2;
			else {
				fflen = (*(data + ext + 2) << 24) +
					(*(data + ext + 3) << 16) +
					(*(data + ext + 4) << 8) +
					*(data + ext + 5);
				datidx = ext + 6;
			}
			printf("[FF] ln: %-4lu data:", fflen);
			break;

		case 0x20:
			/* Consecutive Frame limiter enabled? */
			if (limit_cfs) {
				if (rx_id == src)
					src_cfs++;
				if (rx_id == dst)
					dst_cfs++;
				if (rx_id == bst)
					bst_cfs++;
			}

			printf("[CF] sn: %X    data:", n_pci & 0x0F);
			datidx = ext + 1;
			break;

		case 0x30:
			n_pci &= 0x0F;
			printf("[FC] FC: %d ", n_pci);

			if (n_pci > 3)
				n_pci = 3;

			printf("= %s # ", fc_info[n_pci]);

			printf("BS: %d %s# ", *(data + ext + 1),
			       (*(data + ext + 1))? "":"= off ");

			i = *(data + ext + 2);
			printf("STmin: 0x%02X = ", i);

			if (i < 0x80)
				printf("%d ms", i);
			else if (i > 0xF0 && i < 0xFA)
				printf("%d us", (i & 0x0F) * 100);
			else
				printf("reserved");
			break;

		default:
			printf("[??]");
		}

		if (framelen > max_printlen)
			framelen = max_printlen;

		if (datidx && framelen > datidx) {
			printf(" ");
			for (i = datidx; i < framelen; i++)
				printf("%02X ", *(data + i));

			if (asc) {
				printf("%*s", ((7-ext) - (framelen-datidx))*3 + 5, "-  '");
				for (i = datidx; i < framelen; i++) {
					printf("%c",((*(data + i) > 0x1F) &&
						     (*(data + i) < 0x7F))?
					       *(data + i) : '.');
				}
				printf("'");
			}
			if (uds_output && uds_data_start) {
				int offset = 3;

				if (asc)
					offset = 1;

				printf("%*s", ((7-ext) - (framelen-datidx)) * offset + 3, " - ");
				print_uds_message(*(data + datidx), *(data + datidx + 2));
				uds_data_start = 0;
			}
		}

		if (color)
			printf("%s", ATTRESET);

		printf("\n");
		fflush(stdout);
	}

	close(s);

	return 0;
}
