package com.aero.pcap.capture;

import com.aero.common.utils.BytesUtil;
import com.aero.pcap.classify.*;
import com.aero.pcap.entity.PacketInfo;
import com.aero.pcap.entity.PacketType;
import jpcap.packet.*;
import org.springframework.stereotype.Component;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;

@Component
public class Analyse {
	
	private List<PacketClassify> classify =new ArrayList<>();
	
	LinkedHashMap<String, ArrayList<String>> info = new LinkedHashMap<>();
	
	public void startClassify(Packet p){
		classify.add(new Ethernet());
		classify.add(new IPv4());
		classify.add(new IPv6());
		classify.add(new ARP());
		classify.add(new TCP());
		classify.add(new UDP());
		classify.add(new HTTP());
		for (PacketClassify each : classify) {
			if(each.isBelong(p)){
				each.analyze(p);
				info.put(each.getProtocolName(), each.getData());
			}
		}
	}
	
	public LinkedHashMap<String, ArrayList<String>> getInfo(){
		return info;
	}
	
	public String[] getInfo(Packet p){
		String[] info = new String[7];
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		info[0] = sdf.format(p.sec*1000);
		info[1] = p.len+"";
		EthernetPacket eth=(EthernetPacket)p.datalink;
		info[2] = eth.getSourceAddress()+"";
		info[3] = eth.getDestinationAddress()+"";
		if(p instanceof ARPPacket){
			ARPPacket arp = (ARPPacket) p;
			info[4] = "ARP";
			info[5] = arp.getSenderProtocolAddress()+"";
			info[6] = arp.getTargetProtocolAddress()+"";
		}
		else if (p instanceof IPPacket) {
			if (((IPPacket)p).version==4) {
				info[4] = "IPv4";
			}
			if (((IPPacket)p).version==6) {
				info[4] = "IPv6";
			}
			if (p instanceof UDPPacket) {
				info[4] = "UDP";
			}
			if (p instanceof TCPPacket) {
				info[4] = "TCP";
			}
			IPPacket ip=(IPPacket)p;
			info[5] = ip.src_ip.getHostAddress()+"";
			info[6] = ip.dst_ip.getHostAddress()+"";
		}
		else{
			info[4] = "else";
			info[5] = "Unknown";
			info[6] = "Unknown";
		}
		return info;
	}



	public PacketInfo getDetail(Packet p){
		PacketInfo info = new PacketInfo();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		Date msgTime = null;
		if (p.sec>0) {
			String time = sdf.format(p.sec*1000);
			msgTime = new Date(p.sec*1000);
		}
		info.setMsgTime(msgTime);
		info.setLength(p.len);

		EthernetPacket eth = (EthernetPacket)p.datalink;
		String srcMac = eth.getSourceAddress();
		String destMac = eth.getDestinationAddress();
		info.setSrcMac(srcMac);
		info.setDestMac(destMac);

		if(p instanceof ARPPacket){
			ARPPacket arp = (ARPPacket) p;
			info.setType(PacketType.ARP);
			info.setSrcIp(arp.getSenderProtocolAddress().toString());
			info.setDestIp(arp.getTargetProtocolAddress().toString());
		}
		else if (p instanceof IPPacket) {
			if (((IPPacket)p).version==4) {
				info.setType(PacketType.IPv4);
			}

			if (((IPPacket)p).version==6) {
				info.setType(PacketType.IPv6);
			}

			if (p instanceof UDPPacket) {
				info.setType(PacketType.UDP);
				info.setSrcPort(((UDPPacket) p).src_port);
				info.setDestPort(((UDPPacket) p).dst_port);
			}
			if (p instanceof TCPPacket) {
				info.setType(PacketType.TCP);
				info.setSrcPort(((TCPPacket) p).src_port);
				info.setDestPort(((TCPPacket) p).dst_port);
			}
			IPPacket ip=(IPPacket)p;
			info.setSrcIp(ip.src_ip.getHostAddress());
			info.setDestIp(ip.dst_ip.getHostAddress());
		}
		else{
			info.setType(PacketType.OTHERS);
		}
		info.setContent(p.data);
		info.setHex(BytesUtil.bytes2HexWithBlank(p.data,true));
		return info;
	}
	
}
