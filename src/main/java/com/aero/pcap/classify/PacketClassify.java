package com.aero.pcap.classify;

import jpcap.packet.Packet;

import java.util.ArrayList;

public abstract class PacketClassify
{
	public int layer = DATALINK_LAYER;
	public static int DATALINK_LAYER=0;
	public static int NETWORK_LAYER=1;
	public static int TRANSPORT_LAYER=2;
	public static int APPLICATION_LAYER=3;
	protected ArrayList<String> data = new ArrayList<String>();
	
	public abstract boolean isBelong(Packet packet);
	public abstract void analyze(Packet packet);
	public abstract String getProtocolName();
	
	public ArrayList<String> getData() {
		return data;
	}
	
}
