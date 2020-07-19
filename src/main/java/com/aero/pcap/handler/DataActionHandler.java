package com.aero.pcap.handler;

import com.aero.common.utils.ProtobufUtil;
import com.aero.pcap.capture.Analyse;
import com.aero.pcap.capture.Captor;
import com.aero.pcap.entity.PacketInfo;
import com.aero.pcap.entity.PacketType;
import com.aero.pcap.utils.EscapeUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import jpcap.packet.Packet;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Objects;
import java.util.Queue;

@Slf4j
@Component
@ChannelHandler.Sharable
public class DataActionHandler extends ChannelDuplexHandler {

    private Channel dataPubChannel;
    private Captor capotor;

    @Autowired
    Analyse analyse;


    @Value("${packet.capture.monitor.port}")
    int monitorPort;

    @Value("${packet.capture.monitor.type}")
    String monitorType;

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        super.channelActive(ctx);
        dataPubChannel = ctx.channel();
        capotor = new Captor();
        log.warn("抓包通道开启，开始抓包，抓包类型：{}, 抓包端口：{}", monitorType, monitorPort);
        capotor.chooseDevice();
        capotor.capturePackets();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        log.warn("抓包通道断开，中止抓包");
        capotor.stopCaptureThread();
        capotor.getPackets().clear();
        ctx.close();
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        super.channelRead(ctx, msg);
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
        if(evt instanceof IdleStateEvent){
            IdleStateEvent idleStateEvent = (IdleStateEvent) evt;
            IdleState state = idleStateEvent.state();

            switch (state){
                case READER_IDLE:
                    break;
                case WRITER_IDLE:
                    if(Objects.isNull(capotor)){
                        return;
                    }
                    Queue<Packet> packets = capotor.getPackets();
                    if(Objects.isNull(packets) || packets.size()==0){
                        return;
                    }
                    int size = packets.size();
                    for (int i = 0; i < size; i++) {
                        Packet packet = packets.poll();
                        if(Objects.isNull(packet)){
                            continue;
                        }
                        PacketInfo detail = analyse.getDetail(packet);
                        if(monitorType.equalsIgnoreCase(detail.getType().name()) && (detail.getSrcPort()==monitorPort || detail.getDestPort()==monitorPort)){
                            log.info("读取抓包数据， 类型：{}, SRC端口：{}, DST端口：{}, 消息长度：{}", monitorType, detail.getSrcPort(),detail.getDestPort(),detail.getContent().length);
                            byte[] bytes = ProtobufUtil.serialize(detail);
                            ByteBuf buf = Unpooled.buffer();
                            buf.writeByte(EscapeUtil.SIGN_CODE);
                            buf.writeBytes(bytes);
                            buf.writeByte(EscapeUtil.SIGN_CODE);
                            ByteBuf msg = EscapeUtil.escape(buf);
                            dataPubChannel.writeAndFlush(msg);
                        }
                    }
                    break;
                case ALL_IDLE:
                    break;
                default:
                    break;
            }
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        cause.printStackTrace();
        log.error("DataActionHandler 发生异常：msg = {},e = {}", cause.getMessage(), cause);
        ctx.close();
    }
}
