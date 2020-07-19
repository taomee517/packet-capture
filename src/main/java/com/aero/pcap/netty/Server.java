package com.aero.pcap.netty;

import com.aero.pcap.handler.DataActionHandler;
import com.aero.pcap.handler.FrameEncoder;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.timeout.IdleStateHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Slf4j
@Component
public class Server implements InitializingBean, SmartLifecycle {

    @Value("${packet.capture.server.port}")
    int port;

    @Autowired
    DataActionHandler dataActionHandler;

    @Autowired
    FrameEncoder encoder;

    NioEventLoopGroup boss;
    NioEventLoopGroup workers;
    Channel channel = null;
    boolean running;

    @Override
    public void afterPropertiesSet() throws Exception {

    }

    @Override
    public void start() {
        try {
            ServerBootstrap server = new ServerBootstrap();
            boss = new NioEventLoopGroup();
            workers = new NioEventLoopGroup(8);

            server.group(boss, workers)
                    .childOption(ChannelOption.SO_RCVBUF, 1024*3)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<NioSocketChannel>() {
                        @Override
                        protected void initChannel(NioSocketChannel nioSocketChannel) throws Exception {
                            ChannelPipeline pipeline = nioSocketChannel.pipeline();
                            pipeline.addLast("encoder", encoder);
                            pipeline.addLast("idle", new IdleStateHandler(0,5, 0,TimeUnit.MICROSECONDS));
                            pipeline.addLast("data-action", dataActionHandler);

                        }
                    });
            ChannelFuture channelFuture = server.bind(port).sync();
            log.info("Server binding success, port: {}", port);
            channel = channelFuture.channel();
            running = true;
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    @Override
    public void stop() {
        try {
            channel.close().syncUninterruptibly();
            boss.shutdownGracefully();
            workers.shutdownGracefully();
            boss.awaitTermination(30, TimeUnit.SECONDS);
            workers.awaitTermination(30,TimeUnit.SECONDS);
            running = false;
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    @Override
    public boolean isRunning() {
        return false;
    }
}
