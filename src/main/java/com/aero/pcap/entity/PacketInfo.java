package com.aero.pcap.entity;


import lombok.Data;

import java.util.Date;

/**
 * @author 罗涛
 * @title PacketInfo
 * @date 2020/7/14 19:37
 */
@Data
public class PacketInfo {
    private Date msgTime;
    private int length;
    private String srcMac;
    private String destMac;
    private String srcIp;
    private String descIp;
    private PacketType type;
    private int srcPort;
    private int destPort;
    private String hex;
    private byte[] content;
}
