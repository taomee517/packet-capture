package com.aero.pcap.utils;

import com.aero.common.utils.BytesUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

public class EscapeUtil {
    /**起始符和结束符*/
    public static final byte SIGN_CODE = 0x7e;

    /**转义符号*/
    public static final byte ESCAPE_SIGN = 0x7d;

    /**转义后的7D*/
    public static final byte[] ESCAPE_7D = {0x7d,0x00};

    /**转义后的7E*/
    public static final byte[] ESCAPE_7E = {0x7d,0x01};
    
    public static void unescape(ByteBuf in){
        int srcRdx = in.readerIndex();
        ByteBuf cp = in.readBytes(in.readableBytes());
        in.setIndex(srcRdx,srcRdx);
        try {
            boolean skip = false;
            byte[] temp = new byte[2];
            while (cp.readableBytes()>1){
                byte curr = cp.readByte();
                temp[0] = curr;
                temp[1] = cp.getByte(cp.readerIndex());
                if(skip){
                    in.capacity(in.capacity()-1);
                    skip = false;
                    continue;
                }
                if(BytesUtil.arrayEqual(temp, ESCAPE_7D)){
                    in.writeByte(ESCAPE_SIGN);
                    skip = true;
                    continue;
                }
                if(BytesUtil.arrayEqual(temp,ESCAPE_7E)){
                    in.writeByte(SIGN_CODE);
                    skip = true;
                    continue;
                }
                in.writeByte(curr);
            }
            in.writeByte(temp[1]);
        } finally {
            cp.release();
        }
    }


    public static ByteBuf escape(ByteBuf in){
        ByteBuf out = Unpooled.buffer(in.capacity()*2);
        int capacity = in.capacity();
        out.writeByte(SIGN_CODE);
        in.readerIndex(1);
        while (in.readableBytes()>1){
            byte curr = in.readByte();
            if(curr == ESCAPE_SIGN){
                capacity ++;
                out.capacity(capacity);
                out.writeBytes(ESCAPE_7D);
                continue;
            }
            if(curr == SIGN_CODE){
                capacity ++;
                out.capacity(capacity);
                out.writeBytes(ESCAPE_7E);
                continue;
            }
            out.writeByte(curr);
        }
        out.writeByte(SIGN_CODE);
        return out;
    }
}
