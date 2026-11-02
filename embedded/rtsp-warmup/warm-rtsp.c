/* Bounded loopback RTSP warmup; never records or decodes video, no Flash I/O. */
#define _POSIX_C_SOURCE 200809L
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static int fd = -1;
static char response[16384], session[128];
static const char *base = "rtsp://127.0.0.1:554/stream1";

static int send_all(const char *data, size_t length) {
    while (length) {
        ssize_t n = send(fd, data, length, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        data += n; length -= (size_t)n;
    }
    return 0;
}

static int request(const char *method, const char *url, int sequence, const char *extra) {
    char message[2048];
    int n = snprintf(message, sizeof message,
        "%s %s RTSP/1.0\r\nCSeq: %d\r\nUser-Agent: LocalCamLoopbackWarmup\r\n%s\r\n",
        method, url, sequence, extra);
    if (n <= 0 || n >= (int)sizeof message || send_all(message, (size_t)n)) return -1;
    size_t used = 0, header = 0, body = 0;
    while (used < sizeof response - 1) {
        ssize_t got = recv(fd, response + used, sizeof response - used - 1, 0);
        if (got <= 0) return -1;
        used += (size_t)got; response[used] = 0;
        if (!header) {
            char *end = strstr(response, "\r\n\r\n");
            if (end) {
                header = (size_t)(end + 4 - response);
                char *line = response;
                while (line < end) {
                    if (!strncasecmp(line, "Content-Length:", 15)) body = (size_t)strtoul(line + 15, NULL, 10);
                    char *next = strstr(line, "\r\n");
                    if (!next) break;
                    line = next + 2;
                }
                if (body >= sizeof response - header) return -1;
            }
        }
        if (header && used >= header + body) break;
    }
    return strncmp(response, "RTSP/1.0 200 ", 13) == 0 ? 0 : -1;
}

int localcam_warm_rtsp(void) {
    signal(SIGPIPE, SIG_IGN); alarm(25);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 1;
    struct timeval timeout = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
    struct sockaddr_in peer = {0}; peer.sin_family = AF_INET; peer.sin_port = htons(554);
    inet_pton(AF_INET, "127.0.0.1", &peer.sin_addr);
    if (connect(fd, (struct sockaddr *)&peer, sizeof peer)) { close(fd); return 2; }
    if (request("DESCRIBE", base, 1, "Accept: application/sdp\r\n")) { close(fd); return 3; }
    if (!strstr(response, "a=control:track1") || !strstr(response, "H265/90000")) { close(fd); return 4; }
    char track[128]; snprintf(track, sizeof track, "%s/track1", base);
    if (request("SETUP", track, 2, "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n")) { close(fd); return 5; }
    char *line = response;
    while (*line) {
        if (!strncasecmp(line, "Session:", 8)) {
            line += 8; while (*line == ' ' || *line == '\t') line++;
            size_t length = strcspn(line, ";\r\n ");
            if (!length || length >= sizeof session) break;
            memcpy(session, line, length); session[length] = 0; break;
        }
        char *next = strstr(line, "\r\n"); if (!next) break; line = next + 2;
    }
    if (!session[0]) { close(fd); return 6; }
    char extra[256]; snprintf(extra, sizeof extra, "Session: %s\r\nRange: npt=0-\r\n", session);
    if (request("PLAY", base, 3, extra)) { close(fd); return 7; }
    unsigned long received = 0; char buffer[8192]; time_t started = time(NULL);
    while (time(NULL) - started < 3) {
        ssize_t got = recv(fd, buffer, sizeof buffer, 0);
        if (got <= 0) break;
        received += (unsigned long)got;
    }
    snprintf(extra, sizeof extra, "Session: %s\r\n", session);
    char teardown[512];
    int length = snprintf(teardown, sizeof teardown, "TEARDOWN %s RTSP/1.0\r\nCSeq: 4\r\n%s\r\n", base, extra);
    if (length > 0 && length < (int)sizeof teardown) send_all(teardown, (size_t)length);
    close(fd); alarm(0);
    printf("LOOPBACK_RTSP_WARMUP bytes=%lu\n", received);
    return received >= 4096 ? 0 : 8;
}
