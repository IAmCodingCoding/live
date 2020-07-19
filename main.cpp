#include <iostream>
#include <mutex>
#include "thread"
#include "list"
#include "jrtplib3/rtpsessionparams.h"
#include "jrtplib3/rtpsession.h"
#include "jrtplib3/rtpudpv4transmitter.h"

extern "C" {
#include "libavformat/avformat.h"
}
using namespace std;
using namespace jrtplib;
AVFormatContext *input = nullptr;
AVFormatContext *output = nullptr;

RTPSession *sess;
RTPUDPv4TransmissionParams *transparams;
RTPSessionParams *sessparams;


uint32_t dest_ip;
int max_size = 188;
uint8_t *send_buffer = nullptr;

void init_jrtp(uint16_t localPort, uint16_t destPort, char *ip_str);

void check_error(int rtperr) {
    if (rtperr < 0) {
        printf("jrtp error:%s", RTPGetErrorString(rtperr).c_str());
        exit(-1);
    }
}

char *error2str(int code) {
    static char buffer[1024];
    av_make_error_string(buffer, 1024, code);
    return buffer;
}

int write_packet(void *opaque, uint8_t *buf, int buf_size) {

    int start = 0;
    while (start < buf_size) {
        int len = max_size;
        if (start + len > buf_size - 1) {
            len = buf_size - start;
        }
        memcpy(send_buffer, buf + start, len);
        char extension[200];
//        int size = sprintf(extension, "%s:%s,%s:%s,%s:%s\0", "method", "start", "userId",
//                           "12345678",
//                           "roomId",
//                           "df2b1a88-5e8a-11ea-bc55-0242ac130003");
//        int ret = sess->SendPacketEx(send_buffer, len, 33, false, 10, 0x100, extension,
//                                     size + 1);
        //jrtplib
        int ret = sess->SendPacket(send_buffer, len, 33, false, 10);
        if (ret < 0) {
            printf("jrtplib send packet fail:%s", RTPGetErrorString(ret).c_str());
            return ret;
        }
        start += len;
    }

    return 0;
}

bool is_custom_io = false;
long start = 0;

long current() {
    timeval t;
    gettimeofday(&t, nullptr);
    if (start == 0) {
        start = t.tv_sec * 1000 + t.tv_usec / 1000;
        return 0;
    } else {
        return t.tv_sec * 1000 + t.tv_usec / 1000 - start;
    }
}

int main() {
    if (is_custom_io) {
        init_jrtp(6666, 9000, "127.0.0.1");
    }
    int ret = avformat_open_input(&input, "../test_data/input.flv", nullptr, nullptr);
    if (ret < 0) {
        printf("fail to open video :%s", error2str(ret));
        return ret;
    }
    avformat_find_stream_info(input, nullptr);
    const char *output_file = is_custom_io ? nullptr : "rtp://127.0.0.1:9000";
    const char *format = is_custom_io ? "mpegts" : "rtp_mpegts";
    ret = avformat_alloc_output_context2(&output, nullptr, format,
                                         output_file);

    if (ret < 0) {
        printf("fail to alloc format contexts\n");
        return ret;
    }
    if (is_custom_io) {

        output->pb = avio_alloc_context((unsigned char *) av_malloc(65536), 65536, 1,
                                        nullptr,
                                        nullptr, write_packet,
                                        nullptr);
        output->flags |= (AVFMT_FLAG_CUSTOM_IO | AVFMT_NOFILE);
    }
    if (!(output->flags & AVFMT_NOFILE)) {
        ret = avio_open2(&output->pb, output_file,
                         AVIO_FLAG_WRITE, nullptr, nullptr);
        if (ret < 0) {
            return ret;
        }
    }
    for (int i = 0; i < input->nb_streams; ++i) {
        AVStream *stream = avformat_new_stream(output, nullptr);
        if (stream == nullptr) {
            printf("fail to add audio stream\n");
            return ret;
        }
        ret = avcodec_parameters_copy(stream->codecpar, input->streams[i]->codecpar);
        if (ret < 0) {
            printf("fail to copy parameters from input\n");
            return ret;
        }
    }
    ret = avformat_write_header(output, nullptr);
    if (ret < 0) {
        printf("fail to write header:%s\n", error2str(ret));
        return ret;
    }
    AVPacket *pkt = av_packet_alloc();
    while (true) {
        ret = av_read_frame(input, pkt);
        if (ret < 0) {
            break;
        } else {
            long pts = pkt->pts * av_q2d(input->streams[pkt->stream_index]->time_base) *
                       1000;
            av_packet_rescale_ts(pkt, input->streams[pkt->stream_index]->time_base,
                                 output->streams[pkt->stream_index]->time_base);
            while (current() <= pts) {}
            av_interleaved_write_frame(output, pkt);
        }
        av_packet_unref(pkt);
    }
    av_packet_free(&pkt);
    avformat_close_input(&input);
    if (is_custom_io) {
        av_freep(&output->pb->buffer);
        avio_context_free(&output->pb);

        free(send_buffer);
        delete (sess);
        delete (transparams);
        delete (sessparams);
    }
    if (!(output->flags & AVFMT_NOFILE)) {
        avio_close(output->pb);
    }
    avformat_free_context(output);
    return 0;
}


void init_jrtp(uint16_t local_port, uint16_t dest_port, char *ip_str) {
    sess = new RTPSession();
    dest_ip = inet_addr(ip_str);
    dest_ip = ntohl(dest_ip);
    transparams = new RTPUDPv4TransmissionParams();
    sessparams = new RTPSessionParams();
    sessparams->SetOwnTimestampUnit(1.0 / 10.0);
    sessparams->SetAcceptOwnPackets(true);

    transparams->SetPortbase(local_port);
    int status = sess->Create(*sessparams, transparams);
    check_error(status);
    RTPIPv4Address addr(dest_ip, dest_port);

    status = sess->AddDestination(addr);
    check_error(status);
    send_buffer = static_cast<uint8_t *>(malloc(max_size));
}

