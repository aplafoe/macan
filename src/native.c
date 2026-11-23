#include <errno.h>
#include <ifaddrs.h>
#include <libusb.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static atomic_int stop_requested;
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal flag must be lock-free");

static void macan_stop(int signal) {
    (void)signal;
    atomic_store_explicit(&stop_requested, 1, memory_order_relaxed);
}

int macan_install_shutdown(void) {
    struct sigaction action = {0};
    action.sa_handler = macan_stop;
    action.sa_flags = SA_RESTART;
    sigemptyset(&action.sa_mask);

    const int signals[] = {SIGINT, SIGTERM, SIGHUP};
    sigset_t unblocked;
    sigemptyset(&unblocked);
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i) {
        sigaddset(&unblocked, signals[i]);
        if (sigaction(signals[i], &action, NULL) != 0) {
            return -1;
        }
    }
    int rc = pthread_sigmask(SIG_UNBLOCK, &unblocked, NULL);
    if (rc != 0) {
        errno = rc;
        return -1;
    }
    return 0;
}

int macan_stop_requested(void) {
    return atomic_load_explicit(&stop_requested, memory_order_relaxed);
}

int macan_interface_up(const char *name) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct ifreq request = {0};
    strlcpy(request.ifr_name, name, sizeof(request.ifr_name));
    int rc = ioctl(fd, SIOCGIFFLAGS, &request);
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return rc < 0 ? -1 : (request.ifr_flags & IFF_UP) != 0;
}

int macan_usb_id(libusb_device *device, uint16_t id[2]) {
    struct libusb_device_descriptor desc;
    int rc = libusb_get_device_descriptor(device, &desc);
    if (rc == 0) {
        id[0] = desc.idVendor;
        id[1] = desc.idProduct;
    }
    return rc;
}

int macan_usb_endpoints(libusb_device *device, unsigned char endpoints[2]) {
    struct libusb_config_descriptor *config;
    int rc = libusb_get_active_config_descriptor(device, &config);
    if (rc < 0) {
        return rc;
    }

    rc = LIBUSB_ERROR_NOT_FOUND;
    for (int i = 0; i < config->bNumInterfaces; ++i) {
        const struct libusb_interface *interface = &config->interface[i];
        if (interface->num_altsetting == 0) {
            continue;
        }
        const struct libusb_interface_descriptor *alt = &interface->altsetting[0];
        if (alt->bInterfaceNumber != 0 || alt->bAlternateSetting != 0) {
            continue;
        }

        for (int j = 0; j < alt->bNumEndpoints; ++j) {
            const struct libusb_endpoint_descriptor *ep = &alt->endpoint[j];
            if ((ep->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) == LIBUSB_TRANSFER_TYPE_BULK) {
                int direction = (ep->bEndpointAddress & LIBUSB_ENDPOINT_IN) != 0;
                endpoints[direction] = ep->bEndpointAddress;
            }
        }
        if (endpoints[0] != 0 && endpoints[1] != 0) {
            rc = 0;
        }
        break;
    }

    libusb_free_config_descriptor(config);
    return rc;
}

int macan_mac_address(const char *name, unsigned char address[6]) {
    struct ifaddrs *interfaces;
    if (getifaddrs(&interfaces) != 0) {
        return -1;
    }

    int result = -1;
    for (const struct ifaddrs *it = interfaces; it != NULL; it = it->ifa_next) {
        if (it->ifa_addr == NULL || it->ifa_addr->sa_family != AF_LINK ||
            strcmp(it->ifa_name, name) != 0) {
            continue;
        }
        const struct sockaddr_dl *link = (const struct sockaddr_dl *)it->ifa_addr;
        if (link->sdl_alen == 6) {
            memcpy(address, LLADDR(link), 6);
            result = 0;
            break;
        }
    }

    freeifaddrs(interfaces);
    return result;
}

pcap_t *macan_capture_open(const char *name, const char *filter, char *error, size_t size) {
    char pcap_error[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *capture = pcap_create(name, pcap_error);
    if (capture == NULL) {
        snprintf(error, size, "%s", pcap_error);
        return NULL;
    }

    if (pcap_set_snaplen(capture, 96) != 0 ||
        pcap_set_immediate_mode(capture, 1) != 0 ||
        pcap_activate(capture) < 0) {
        snprintf(error, size, "%s", pcap_geterr(capture));
        goto fail;
    }
    if (pcap_datalink(capture) != DLT_EN10MB) {
        snprintf(error, size, "expected an Ethernet interface");
        goto fail;
    }
    if (pcap_setnonblock(capture, 1, pcap_error) != 0) {
        snprintf(error, size, "%s", pcap_error);
        goto fail;
    }

    struct bpf_program program;
    if (pcap_compile(capture, &program, filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        snprintf(error, size, "%s", pcap_geterr(capture));
        goto fail;
    }
    int rc = pcap_setfilter(capture, &program);
    pcap_freecode(&program);
    if (rc != 0) {
        snprintf(error, size, "%s", pcap_geterr(capture));
        goto fail;
    }
    return capture;

fail:
    pcap_close(capture);
    return NULL;
}

int macan_capture_next(pcap_t *capture, unsigned char *packet, size_t size, int64_t time[2]) {
    struct pcap_pkthdr *header;
    const unsigned char *data;
    int rc = pcap_next_ex(capture, &header, &data);
    if (rc != 1) {
        return rc;
    }

    size_t length = header->caplen < size ? header->caplen : size;
    memcpy(packet, data, length);
    time[0] = header->ts.tv_sec;
    time[1] = header->ts.tv_usec;
    return (int)length;
}
