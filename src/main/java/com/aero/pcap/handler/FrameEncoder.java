package com.aero.pcap.handler;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * @author 罗涛
 * @title FrameEncoder
 * @date 2020/5/8 11:26
 */
@ChannelHandler.Sharable
@Component @Slf4j
public class FrameEncoder extends MessageToByteEncoder {
    @Override
    protected void encode(ChannelHandlerContext ctx, Object msg, ByteBuf out) throws Exception {
        if (msg instanceof byte[]) {
            byte[] captureContent = ((byte[]) msg);
            ByteBuf buf = Unpooled.wrappedBuffer(captureContent);
            out.writeBytes(buf);
        }else if(msg instanceof ByteBuf){
           out.writeBytes(((ByteBuf) msg));
        } else {
            log.error("抓包内容格式不对，请转为字节数组格式");
        }
    }
}
