package com.example.isup;

import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.DelimiterBasedFrameDecoder;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
//TIP 要<b>运行</b>代码，请按 <shortcut actionId="Run"/> 或
// 点击装订区域中的 <icon src="AllIcons.Actions.Execute"/> 图标。
public class Main {

    // 服务器端处理器
    static class EchoServerHandler extends ChannelInboundHandlerAdapter {
        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            String message = (String) msg;
            System.out.println("服务器收到消息: " + message);

            // 将消息回传给客户端
            ctx.writeAndFlush("Echo: " + message + "\n");
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            cause.printStackTrace();
            ctx.close();
        }
    }

    // 服务器端
    static class EchoServer {
        private int port;

        public EchoServer(int port) {
            this.port = port;
        }

        public void start() throws InterruptedException {
            EventLoopGroup bossGroup = new NioEventLoopGroup(); // 接受进来的连接
            EventLoopGroup workerGroup = new NioEventLoopGroup(); // 处理被接受的连接
            try {
                ServerBootstrap b = new ServerBootstrap(); // 引导辅助程序
                b.group(bossGroup, workerGroup)
                        .channel(NioServerSocketChannel.class) // 指定通道类型
                        .childHandler(new ChannelInitializer<SocketChannel>() { // 绑定I/O事件的处理类
                            @Override
                            protected void initChannel(SocketChannel ch) throws Exception {
                                ChannelPipeline pipeline = ch.pipeline();

                                // 添加分隔符解码器，使用换行符作为分隔符
                                ByteBuf delimiter = Unpooled.copiedBuffer("\n".getBytes());
                                pipeline.addLast(new DelimiterBasedFrameDecoder(1024, delimiter));
                                pipeline.addLast(new StringDecoder());
                                pipeline.addLast(new StringEncoder());
                                pipeline.addLast(new EchoServerHandler());
                            }
                        })
                        .option(ChannelOption.SO_BACKLOG, 128) // 设置队列大小
                        .childOption(ChannelOption.SO_KEEPALIVE, true); // 保持连接

                System.out.println("服务器启动，监听端口: " + port);
                ChannelFuture f = b.bind(port).sync(); // 绑定端口，开始接收进来的连接

                f.channel().closeFuture().sync(); // 等待服务器 socket 关闭
            } finally {
                workerGroup.shutdownGracefully();
                bossGroup.shutdownGracefully();
            }
        }
    }

    // 客户端处理器
    static class EchoClientHandler extends ChannelInboundHandlerAdapter {
        private final String message;

        public EchoClientHandler(String message) {
            this.message = message;
        }

        @Override
        public void channelActive(ChannelHandlerContext ctx) {
            // 连接建立后发送消息
            ctx.writeAndFlush(message + "\n");
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) {
            System.out.println("客户端收到消息: " + msg);
            ctx.close(); // 收到响应后关闭连接
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            cause.printStackTrace();
            ctx.close();
        }
    }

    // 客户端
    static class EchoClient {
        private final String host;
        private final int port;
        private final String message;

        public EchoClient(String host, int port, String message) {
            this.host = host;
            this.port = port;
            this.message = message;
        }

        public void start() throws InterruptedException {
            EventLoopGroup group = new NioEventLoopGroup();
            try {
                Bootstrap b = new Bootstrap();
                b.group(group)
                        .channel(NioSocketChannel.class)
                        .handler(new ChannelInitializer<SocketChannel>() {
                            @Override
                            protected void initChannel(SocketChannel ch) throws Exception {
                                ChannelPipeline pipeline = ch.pipeline();

                                // 添加分隔符解码器
                                ByteBuf delimiter = Unpooled.copiedBuffer("\n".getBytes());
                                pipeline.addLast(new DelimiterBasedFrameDecoder(1024, delimiter));
                                pipeline.addLast(new StringDecoder());
                                pipeline.addLast(new StringEncoder());
                                pipeline.addLast(new EchoClientHandler(message));
                            }
                        });

                ChannelFuture f = b.connect(host, port).sync();

                f.channel().closeFuture().sync();
            } finally {
                group.shutdownGracefully();
            }
        }
    }

    public static void main(String[] args) {
        // 启动服务器线程
        Thread serverThread = new Thread(() -> {
            try {
                // new EchoServer(7660).start();
                new IsupServerConfig().run("test");
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        serverThread.start();

        // 等待服务器启动
//        try {
//            Thread.sleep(2000);
//        } catch (InterruptedException e) {
//            e.printStackTrace();
//        }
//
//        // 创建并启动客户端
//        System.out.println("启动客户端...");
//        new EchoClient("localhost", 8089, "Hello Netty!").start();
    }
}