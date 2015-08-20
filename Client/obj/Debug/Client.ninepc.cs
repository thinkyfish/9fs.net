/*
 * Copy me if you can.
 * by 20h
 */

using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Collections.Generic;

namespace ninepc
{
	public enum proto : uint {
		Blocksize = 		65536,
		
		Tversion =		100,
		Rversion,
		Tauth,
		Rauth,
		Tattach,
		Rattach,
		Terror,
		Rerror,
		Tflush,
		Rflush,
		Twalk,
		Rwalk,
		Topen,
		Ropen,
		Tcreate,
		Rcreate,
		Tread,
		Rread,
		Twrite,
		Rwrite,
		Tclunk,
		Rclunk,
		Tremove,
		Rremove,
		Tstat,
		Rstat,
		Twstat,
		Rwstat,

		BIT64SZ =		8,
		BIT32SZ =		4,
		BIT16SZ =		2,
		BIT8SZ =			1,
		QIDSZ =			(BIT8SZ + BIT32SZ + BIT64SZ),
		
		MAXWELEM =		16,
		STATFIXLEN =		(BIT16SZ + QIDSZ + 5 * BIT16SZ + 4 * BIT32SZ + BIT64SZ),
		MAXPKTSIZE =		8192,
		IOHDRSIZE =			(BIT8SZ + BIT16SZ + 3 * BIT32SZ + BIT64SZ),

		//Dir.mode mode bits
		DMDIR = 			0x80000000,
		DMAPPEND = 	0x40000000,
		DMEXCL =			0x20000000,
		DMMOUNT =		0x10000000,
		DMAUTH =			0x08000000,
		DMTMP =			0x04000000,
		DMNONE =			0xFC000000,

		//Qid type bits
		QTDIR =		0x80,		
		QTAPPEND =	0x40,		
		QTEXCL =		0x20,		
		QTMOUNT =		0x10,		
		QTAUTH =		0x08,	
		QTTMP =		0x04,		
		QTSYMLINK =	0x02,		
		QTFILE =		0x00,

		OREAD =	0,	/* open for read */
		OWRITE = 1,	/* write */
		ORDWR =	2,	/* read and write */
		OEXEC =	3,	/* execute, == read but check execute permission */
		OTRUNC =	16,	/* or'ed in (except for exec), truncate file first */
		ORCLOSE =	64,	/* or'ed in, remove on close */
		ODIRECT =	128,	/* or'ed in, direct access */
		OEXCL =	0x1000,	/* or'ed in, exclusive use (create only) */
		OAPPEND =	0x4000,	/* or'ed in, append only */
	}

	struct Qid {
		public ulong path;
		public uint vers;
		public byte type;
	}
	
	struct Dir {
		public int status;
	
		public ushort type;
		public uint dev;

		public Qid qid;
		public uint mode;
		public uint atime;
		public uint mtime;
		public ulong length;
		public string name;
		public string uid;
		public string gid;
		public string muid;
	}

	struct Fcall {
		public int status;
	
		public byte type;
		public int fid;
		public ushort tag;

		public uint msize;
		public string version;

		public ushort oldtag;

		public string ename;

		public Qid qid;
		public uint iounit;

		public Qid aqid;

		public int afid;
		public string uname;
		public string aname;

		public uint perm;
		public string name;
		public byte mode;

		public int newfid;
		public ushort nwname;
		public string[] wname;

		public ushort nwqid;
		public Qid[] wqid;

		public ulong offset;
		public uint count;
		public Byte[] data;

		public ushort nstat;
		public Byte[] stat;
	}
	
	class ninepexception : Exception
	{
		public ninepexception(string str)
		{
			Console.WriteLine("9P error: {0}", str);
		}
	}
	
	class ninep
	{
		public static void printPacket(Byte[] pkt, string type){
			int size = (int)BitConverter.ToUInt32(pkt, 0);
			Console.WriteLine (type + "|" + Encoding.Default.GetString (pkt,0,size));
			Console.WriteLine (type + "|" + BitConverter.ToString (pkt,0,size));
		}
		Socket sock;
		public Fcall fT;
		public Fcall fR;
		
		public Dir dir;

		public Byte[] pktT;
		public Byte[] pktR;
		
		public Byte[] readbuf;
		
		public ushort tag;
		public int root;
		public int afid;
		public int cwd;
		public int fid;
		public int ffid;
		
		public string uname;
		public string aname;
		
		public uint mmsgsz;
		public uint mdatasz;

		public string modestr(uint mode)
		{
			string[] bits;
			string d;
			
			bits = new string[8] {"---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"};
			d = "";
			if((mode & (uint)proto.DMDIR) > 0)
				d += "d";
			if((mode & (uint)proto.DMAPPEND) > 0)
				d += "a";
			if((mode & (uint)proto.DMEXCL) > 0)
				d += "e";
			if((mode & (uint)proto.DMMOUNT) > 0)
				d += "m";
			if((mode & (uint)proto.DMAUTH) > 0)
				d += "u";
			if((mode & (uint)proto.DMTMP) > 0)
				d += "t";
			if((mode & (uint)proto.DMNONE) == 0)
				d = "-";

			return string.Format(null, "{0}{1}{2}{3}", new Object[] {d, bits[(mode >> 6) & 0x07],
								bits[(mode >> 3) & 0x07], bits[mode & 0x07]});
		}

		public void connect(string host, int port)
		{
			IPHostEntry iphost;
			IPAddress[] addr;
			EndPoint ep;

			tag = 10;
			root = 9;
			afid = -1;
			cwd = 7;
			fid = 6;
			ffid = 5;
			mmsgsz = (uint)proto.MAXPKTSIZE;
			mdatasz = mmsgsz - (uint)proto.IOHDRSIZE;
			
			uname = "andrey";
			aname = "";
			
			fT = new Fcall();
			pktT = new Byte[mmsgsz];
			
			iphost = Dns.GetHostEntry(host);
			addr = iphost.AddressList;
			ep = new IPEndPoint(addr[0], port);
			
			sock = new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp);
			try {
				sock.Connect(ep);
				Console.WriteLine("Connected");
			} catch(Exception ex) {
				throw new ninepexception(ex.ToString());
			}
		}
		
		public void shutdown()
		{
			sock.Shutdown(SocketShutdown.Both);
			sock.Close();
			Console.WriteLine("Disconnected");
		}

		public ulong getulong(Byte[] data, uint dp)
		{
			return BitConverter.ToUInt64(data, (int)dp);
		}
		
		public uint getuint(Byte[] data, uint dp)
		{
			return BitConverter.ToUInt32(data, (int)dp);
		}
		
		public ushort getushort(Byte[] data, uint dp)
		{
			return BitConverter.ToUInt16(data, (int)dp);
		}
		
		public string getstring(Byte[] data, uint dp)
		{
			ushort len;
			char[] strdata;
			string ret;
        	UTF8Encoding utf8;
        	
        	utf8 = new UTF8Encoding();
			//Console.WriteLine ("dp=" + dp);
			len = getushort(data, dp);
			//Console.WriteLine ("len=" + len);
			dp += (uint)proto.BIT16SZ;
			
			strdata = new char[utf8.GetCharCount(data, (int)dp, (int)len)];
			utf8.GetChars(data, (int)dp, (int)len, strdata, 0);
			ret = new string(strdata);
			
			return ret;
		}
		
		public string convstring(Byte[] data)
		{
			char[] strdata;
			string ret;
        	UTF8Encoding utf8;
        	
        	utf8 = new UTF8Encoding();
			
			strdata = new char[utf8.GetCharCount(data, 0, data.Length)];
			utf8.GetChars(data, 0, data.Length, strdata, 0);
			ret = new string(strdata);
			
			return ret;
		}

		public Qid getqid(Byte[] data, uint dp)
		{
			Qid q;
			
			q.type = data[dp];
			dp += (uint)proto.BIT8SZ;
			q.vers = getuint(data, dp);
			dp += (uint)proto.BIT32SZ;
			q.path = getulong(data, dp);
			dp += (uint)proto.BIT64SZ;
			
			return q;
		}
		
		public void putulong(Byte[] data, uint dp, ulong var)
		{
			Byte[] datavar;
			
			datavar = BitConverter.GetBytes(var);
			Array.Copy(datavar, 0, data, dp, (uint)datavar.Length);
		}
		
		public void putuint(Byte[] data, uint dp, uint var)
		{
			Byte[] datavar;
			
			datavar = BitConverter.GetBytes(var);
			Array.Copy(datavar, 0, data, dp, (uint)datavar.Length);
		}
		
		public void putushort(Byte[] data, uint dp, ushort var)
		{
			Byte[] datavar;
			
			datavar = BitConverter.GetBytes(var);
			Array.Copy(datavar, 0, data, dp, (uint)datavar.Length);
		}
		
		public void putstring(Byte[] data, uint dp, string var)
		{
			Byte[] strdata;
        	UTF8Encoding utf8;
        	
        	utf8 = new UTF8Encoding();
			
			putushort(data, dp, (ushort)var.Length);
			dp += (uint)proto.BIT16SZ;
			
			strdata = utf8.GetBytes(var);
			Array.Copy(strdata, 0, data, dp, (uint)strdata.Length);
		}			

		public void putqid(Byte[] data, uint dp, Qid q)
		{
			data[dp] = q.type;
			dp += (uint)proto.BIT8SZ;
			putuint(data, dp, q.vers);
			dp += (uint)proto.BIT32SZ;
			putulong(data, dp, q.path);
			dp += (uint)proto.BIT64SZ;
		}

		public Byte[] recvn(int n)
		{
			Byte[] data;
			int r, i;

			r = 0;
			data = new Byte[n];

			while(r < n) {
				i = sock.Receive(data, r, data.Length - r, SocketFlags.None);
				r += i;
				if(i == 0)
					break;
			}
			
			return data;
		}

		public Byte[] read9pmsg()
		{
			Byte[] data, len, pkt;
			uint pktlen;

			len = recvn((int)proto.BIT32SZ);
			pktlen = getuint(len, 0);
			//if (pktlen - (int)proto.BIT32SZ > mmsgsz) {
			//	return new Byte[0];
				//throw new ninepexception ("pkt too small/large");
			//}
			if (pktlen == 0)
				pktlen = 100;
			//Console.WriteLine("len={0}, mmsgsz={1}", BitConverter.ToString(len), mmsgsz);
			data = recvn((int)pktlen - (int)proto.BIT32SZ);
			//Console.WriteLine("data={0}", BitConverter.ToString(data));
			pkt = new Byte[pktlen];
			len.CopyTo(pkt, 0);
			data.CopyTo(pkt, (int)proto.BIT32SZ);
			
			return pkt;
		}
		
		public void send9pmsg(Byte[] pkt)
		{
			int len;

			len = (int)getuint(pkt, 0);
			
			try {
				sock.Send(pkt, len, SocketFlags.None);
			} catch(Exception ex) {
				Console.WriteLine("Error send9pmsg: {0}", ex.ToString());
				throw new ninepexception("send9pmsg failed");
			}
		}
		
		public Fcall convM2S(Byte[] pkt)
		{
			Byte[] buf;
			uint len, pp, i;
			Fcall f;

			f = new Fcall();
			buf = new Byte[(int)proto.BIT32SZ];
			pp = 0;

			if(pkt.Length < (int)proto.BIT32SZ + (int)proto.BIT8SZ + (int)proto.BIT16SZ)
				return f;
			len = getuint(pkt, 0);
			if(len < (int)proto.BIT32SZ + (int)proto.BIT8SZ + (int)proto.BIT16SZ)
				return f;
			pp += (uint)proto.BIT32SZ;

			f.type = pkt[pp];
			pp += (uint)proto.BIT8SZ;
			Array.Copy(pkt, pp, buf, (uint)proto.BIT32SZ - (uint)proto.BIT16SZ, (uint)proto.BIT16SZ);  
			f.tag = getushort(pkt, pp);
			pp += (uint)proto.BIT16SZ;
			
			switch(f.type) {
			default:
				return f;
			case (byte)proto.Tversion:
				if(pp + (uint)proto.BIT32SZ > len)
					return f;
				Array.Copy(pkt, pp, buf, (uint)proto.BIT32SZ - (uint)proto.BIT16SZ, (uint)proto.BIT16SZ);
				f.msize = getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.version = getstring(pkt, pp);
				pp += (uint)f.version.Length;
				break;
			case (byte)proto.Tflush:
				if(pp + (uint)proto.BIT16SZ > len)
					return f;
				f.oldtag = getushort(pkt, pp);
				pp += (uint)proto.BIT16SZ;
				break;
			case (byte)proto.Tauth:
				if (pp + (uint)proto.BIT32SZ > len)
					return f;
				f.afid = (int)getuint (pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.uname = getstring (pkt, pp);
				pp += (uint)proto.BIT16SZ + (uint)f.uname.Length;
				f.aname = getstring(pkt, pp);
				pp += (uint)proto.BIT16SZ + (uint)f.aname.Length;
				break;
			case (byte)proto.Tattach:
				if(pp + (uint)proto.BIT32SZ + (uint)proto.BIT32SZ > len)
					return f;
				f.fid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.afid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.uname = getstring(pkt, pp);
				pp  += (uint)proto.BIT16SZ + (uint)f.uname.Length;
				f.aname = getstring(pkt, pp);
				pp  += (uint)proto.BIT16SZ + (uint)f.aname.Length;
				break;
			case (byte)proto.Twalk:
				if (pp + (uint)proto.BIT32SZ + (uint)proto.BIT32SZ + (uint)proto.BIT16SZ > len)
					return f;
				f.fid = (int)getuint (pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.newfid = (int)getuint (pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.nwname = getushort (pkt, pp);
				pp += (uint)proto.BIT16SZ;
				if(f.nwname > (int)proto.MAXWELEM)
					return f;
				f.wname = new string[f.nwname];
				for(i = 0; i < f.nwname; i++) {
					f.wname[i] = getstring(pkt, pp);
					pp += (uint)f.wname[i].Length + (uint)proto.BIT16SZ;
				}
				break;
			case (byte)proto.Topen:
				if(pp + (uint)proto.BIT32SZ + (uint)proto.BIT8SZ > len)
					return f;
				f.fid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.mode = pkt[pp];
				pp += (uint)proto.BIT8SZ;
				break;
			case (byte)proto.Tcreate:
				if(pp + (uint)proto.BIT32SZ > len)
					return f;
				f.fid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.name = getstring(pkt, pp);
				pp += (uint)proto.BIT16SZ + (uint)f.name.Length;
				if(pp + (uint)proto.BIT32SZ + (uint)proto.BIT8SZ > len)
					return f;
				f.perm = getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.mode = pkt[pp];
				pp += (uint)proto.BIT8SZ;
				break;
			case (byte)proto.Tread:
				if(pp + (uint)proto.BIT32SZ + (uint)proto.BIT64SZ + (uint)proto.BIT32SZ > len)
					return f;
				f.fid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.offset = getulong(pkt, pp);
				pp += (uint)proto.BIT64SZ;
				f.count = getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Twrite:
				if(pp + (uint)proto.BIT32SZ + (uint)proto.BIT64SZ + (uint)proto.BIT32SZ > len)
					return f;
				f.fid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.offset = getulong(pkt, pp);
				pp += (uint)proto.BIT64SZ;
				f.count = getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				if(pp + f.count > len)
					return f;
				f.data = new Byte[f.count];
				Array.Copy(pkt, pp, f.data, 0, f.count);
				pp += f.count;
				break;
			case (byte)proto.Tclunk:
			case (byte)proto.Tremove:
			case (byte)proto.Tstat:
				if(pp + (uint)proto.BIT32SZ > len)
					return f;
				f.fid = (int)getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Twstat:
				if (pp + (uint)proto.BIT32SZ + (uint)proto.BIT16SZ > len)
					return f;
				f.fid = (int)getuint (pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.nstat = getushort (pkt, pp);
				//pp += (uint)proto.BIT16SZ; convm2d assumes size is still in byte[]
				if (pp + f.nstat + (uint)proto.BIT16SZ > len)
					return f;
				f.stat = new Byte[f.nstat + (uint)proto.BIT16SZ];
				Array.Copy (pkt, pp, f.stat, 0, f.nstat);
				//Console.WriteLine ("f.nstat={0}, f.stat={1}", f.nstat, BitConverter.ToString(f.stat));
				pp += (uint)f.stat.Length;
				break;
				
			case (byte)proto.Rversion:
				if(pp + (uint)proto.BIT32SZ > len)
					return f;
				f.msize = getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				f.version = getstring(pkt, pp);
				pp += (uint)f.version.Length;
				break;
			case (byte)proto.Rerror:
				f.ename = getstring(pkt, pp);
				pp += (uint)f.ename.Length;
				break;
			case (byte)proto.Rauth:
				f.aqid = getqid(pkt, pp);
				pp += (uint)proto.QIDSZ;
				break;
			case (byte)proto.Rattach:
				f.qid = getqid(pkt, pp);
				pp += (uint)proto.QIDSZ;
				break;
			case (byte)proto.Rwalk:
				if(pp + (uint)proto.BIT16SZ > len)
					return f;
				f.nwqid = getushort(pkt, pp);
				pp += (uint)proto.BIT16SZ;
				if(f.nwqid > (int)proto.MAXWELEM)
					return f;
				f.wqid = new Qid[f.nwqid];
				for(i = 0; i < f.nwqid; i++) {
					f.wqid[i] = getqid(pkt, pp);
					pp += (uint)proto.QIDSZ;
				}
				break;
			case (byte)proto.Ropen:
			case (byte)proto.Rcreate:
				f.qid = getqid(pkt, pp);
				pp += (uint)proto.QIDSZ;
				if(pp + (uint)proto.BIT32SZ > len)
					return f;
				f.iounit = getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Rread:
				if(pp + (uint)proto.BIT32SZ > len)
					return f;
				f.count = getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				if(pp + f.count > len)
					return f;
				f.data = new Byte[f.count];
				Array.Copy(pkt, pp, f.data, 0, f.count);
				pp += f.count;
				break;
			case (byte)proto.Rwrite:
				if(pp + (uint)proto.BIT32SZ > len)
					return f;
				f.count = getuint(pkt, pp);
				pp += (uint)proto.BIT32SZ;
				break;

			case (byte)proto.Rremove:
			case (byte)proto.Rwstat:
				break;
			case (byte)proto.Rclunk:
			case (byte)proto.Rflush:
				if (pp + (uint)proto.BIT16SZ > len)
					return f;
				f.tag = getushort (pkt, pp);
				pp += (uint)proto.BIT16SZ;
				break;
			case (byte)proto.Rstat:
				if(pp + (uint)proto.BIT16SZ > len)
					return f;
				f.nstat = getushort(pkt, pp);
				//pp += (uint)proto.BIT16SZ; convM2D assumes length is still in the message
				if(pp + f.nstat > len)
					return f;
				f.stat = new Byte[f.nstat + (uint)proto.BIT16SZ];
				Array.Copy(pkt, pp, f.stat, 0, f.nstat + (uint)proto.BIT16SZ);
				pp += (uint)f.nstat + (uint)proto.BIT16SZ;
				break;
			}
			
			if(pp <= len)
				f.status = 1;
				
			return f;
		}

		public uint sizeS2M(Fcall f)
		{
			uint n, i;
			
			n = (uint)proto.BIT32SZ + (uint)proto.BIT8SZ + (uint)proto.BIT16SZ;
			switch(f.type) {
			default:
				return 0;
			case (byte)proto.Tversion:
			case (byte)proto.Rversion:
				n += (uint)proto.BIT32SZ + (uint)proto.BIT16SZ + (uint)f.version.Length;
				break;
			case (byte)proto.Tflush:
				n += (uint)proto.BIT16SZ;
				break;
			case (byte)proto.Tauth:
				n += (uint)proto.BIT32SZ + 2 * (uint)proto.BIT16SZ + (uint)f.uname.Length + (uint)f.aname.Length;
				break;
			case (byte)proto.Tattach:
				n += 2 * (uint)proto.BIT32SZ + 2 * (uint)proto.BIT16SZ + (uint)f.uname.Length + (uint)f.aname.Length;
				break;
			case (byte)proto.Twalk:
				n += 2 * (uint)proto.BIT32SZ + (uint)proto.BIT16SZ;
				for(i = 0; i < f.nwname; i++)
					n += (uint)f.wname[i].Length + (uint)proto.BIT16SZ;
				break;
			case (byte)proto.Topen:
				n += (uint)proto.BIT32SZ + (uint)proto.BIT8SZ;
				break;
			case (byte)proto.Tcreate:
				n += 2 * (uint)proto.BIT32SZ + (uint)proto.BIT8SZ + (uint)proto.BIT16SZ + (uint)f.name.Length;
				break;
			case (byte)proto.Twrite:
				n += 2 * (uint)proto.BIT32SZ + (uint)proto.BIT64SZ + f.count;
				break;
			case (byte)proto.Tread:
				n += 2 * (uint)proto.BIT32SZ + (uint)proto.BIT64SZ;
				break;
			case (byte)proto.Tclunk:
			case (byte)proto.Tremove:
			case (byte)proto.Tstat:
			case (byte)proto.Rwrite:
				n += (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Twstat:
				//n += (uint)proto.BIT32SZ + 2 * (uint)proto.BIT16SZ + f.nstat;
				n += (uint)proto.BIT32SZ + (uint)f.stat.Length;
				break;

			case (byte)proto.Rerror:
				n += (uint)proto.BIT16SZ + (uint)f.ename.Length;
				break;
			case (byte)proto.Rflush:
			case (byte)proto.Rclunk:
			case (byte)proto.Rremove:
			case (byte)proto.Rwstat:
				break;
			case (byte)proto.Rauth:
			case (byte)proto.Rattach:
				n += (uint)proto.QIDSZ;
				break;
			case (byte)proto.Rwalk:
				n += (uint)proto.BIT16SZ + f.nwqid * (uint)proto.QIDSZ;
				break;
			case (byte)proto.Ropen:
			case (byte)proto.Rcreate:
				n += (uint)proto.QIDSZ + (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Rread:
				n += (uint)proto.BIT32SZ + f.count;
				break;
			case (byte)proto.Rstat:
				n += (uint)f.stat.Length;//(uint)proto.BIT16SZ + f.nstat;
				break;
			}
			
			return n;
		}

		public uint convS2M(Fcall f, Byte[] pkt)
		{
			uint size, i, pp;
			
			size = sizeS2M(f);
			if(size == 0)
				return 0;
			if(size > pkt.Length)
				return 0;
			pp = 0;
			putuint(pkt, pp, size);
			pp += (uint)proto.BIT32SZ;
			pkt[pp] = f.type;
			pp += (uint)proto.BIT8SZ;
			putushort(pkt, pp, f.tag);
			pp += (uint)proto.BIT16SZ;
			
			switch(f.type) {
			default:
				return 0;
			case (byte)proto.Tversion:
				putuint(pkt, pp, f.msize);
				pp += (uint)proto.BIT32SZ;
				putstring(pkt, pp, f.version);
				pp += (uint)proto.BIT16SZ + (uint)f.version.Length;
				break;
			case (byte)proto.Tflush:
				putushort(pkt, pp, f.oldtag);
				pp += (uint)proto.BIT16SZ;
				break;
			case (byte)proto.Tauth:
				putuint(pkt, pp, (uint)f.afid);
				pp += (uint)proto.BIT32SZ;
				putstring(pkt, pp, f.uname);
				pp += (uint)proto.BIT16SZ + (uint)f.uname.Length;
				putstring(pkt, pp, f.aname);
				pp += (uint)proto.BIT16SZ + (uint)f.aname.Length;
				break;
			case (byte)proto.Tattach:
				putuint(pkt, pp, (uint)f.fid);
				pp += (uint)proto.BIT32SZ;
				putuint(pkt, pp, (uint)f.afid);
				pp += (uint)proto.BIT32SZ;
				putstring(pkt, pp, f.uname);
				pp += (uint)proto.BIT16SZ + (uint)f.uname.Length;
				putstring(pkt, pp, f.aname);
				pp += (uint)proto.BIT16SZ + (uint)f.aname.Length;
				break;
			case (byte)proto.Twalk:
				putuint(pkt, pp, (uint)f.fid);
				pp += (uint)proto.BIT32SZ;
				putuint(pkt, pp, (uint)f.newfid);
				pp += (uint)proto.BIT32SZ;
				putushort(pkt, pp, f.nwname);
				pp += (uint)proto.BIT16SZ;
				if(f.nwname > (uint)proto.MAXWELEM)
					return 0;
				for(i = 0; i < f.nwname; i++) {
					putstring(pkt, pp, f.wname[i]);
					pp += (uint)proto.BIT16SZ + (uint)f.wname[i].Length;
				}
				break;
			case (byte)proto.Topen:
				putuint(pkt, pp, (uint)f.fid);
				pp += (uint)proto.BIT32SZ;
				pkt[pp] = f.mode;
				pp += (uint)proto.BIT8SZ;
				break;
			case (byte)proto.Tcreate:
				putuint(pkt, pp, (uint)f.fid);
				pp += (uint)proto.BIT32SZ;
				putstring(pkt, pp, f.name);
				pp += (uint)proto.BIT16SZ + (uint)f.name.Length;
				putuint(pkt, pp, f.perm);
				pp += (uint)proto.BIT32SZ;
				pkt[pp] = f.mode;
				pp += (uint)proto.BIT8SZ;
				break;
			case (byte)proto.Tread:
				putuint(pkt, pp, (uint)f.fid);
				pp += (uint)proto.BIT32SZ;
				putulong(pkt, pp, f.offset);
				pp += (uint)proto.BIT64SZ;
				putuint(pkt, pp, f.count);
				pp += (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Twrite:
				putuint(pkt, pp, (uint)f.fid);
				pp += (uint)proto.BIT32SZ;
				putulong(pkt, pp, f.offset);
				pp += (uint)proto.BIT64SZ;
				putuint(pkt, pp, f.count);
				pp += (uint)proto.BIT32SZ;
				Array.Copy(f.data, 0, pkt, pp, f.count);
				pp += f.count;
				break;
			case (byte)proto.Tclunk:
			case (byte)proto.Tremove:
			case (byte)proto.Tstat:
				putuint(pkt, pp, (uint)f.fid);
				pp += (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Twstat:
				putuint(pkt, pp, (uint)f.fid);
				pp += (uint)proto.BIT32SZ;
				///putushort(pkt, pp, f.nstat); // this is included in f.stat

				Array.Copy(f.stat, 0, pkt, pp, f.stat.Length);
				pp += (uint)f.stat.Length;
				break;

			case (byte)proto.Rversion:
				putuint(pkt, pp, f.msize);
				pp += (uint)proto.BIT32SZ;
				putstring(pkt, pp, f.version);
				pp += (uint)proto.BIT16SZ + (uint)f.version.Length;
				break;
			case (byte)proto.Rerror:
				putstring(pkt, pp, f.ename);
				pp += (uint)proto.BIT16SZ + (uint)f.ename.Length;
				break;
			case (byte)proto.Rflush:
			case (byte)proto.Rclunk:
			case (byte)proto.Rremove:
			case (byte)proto.Rwstat:
				break;
			case (byte)proto.Rauth:
				putqid(pkt, pp, f.aqid);
				pp += (uint)proto.QIDSZ;
				break;
			case (byte)proto.Rattach:
				putqid(pkt, pp, f.qid);
				pp += (uint)proto.QIDSZ;
				break;
			case (byte)proto.Rwalk:
				putushort(pkt, pp, f.nwqid);
				pp += (uint)proto.BIT16SZ;
				if(f.nwqid > (uint)proto.MAXWELEM)
					return 0;
				for(i = 0; i < f.nwqid; i++) {
					putqid(pkt, pp, f.wqid[i]);
					pp += (uint)proto.QIDSZ;
				}
				break;
			case (byte)proto.Ropen:
			case (byte)proto.Rcreate:
				putqid(pkt, pp, f.qid);
				pp += (uint)proto.QIDSZ;
				putuint(pkt, pp, f.iounit);
				pp += (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Rread:
				putuint(pkt, pp, f.count);
				pp += (uint)proto.BIT32SZ;
				Array.Copy(f.data, 0, pkt, pp, f.count);
				pp += f.count;
				break;
			case (byte)proto.Rwrite:
				putuint(pkt, pp, f.count);
				pp += (uint)proto.BIT32SZ;
				break;
			case (byte)proto.Rstat:
				//putushort(pkt, pp, f.nstat);
				//pp += (uint)proto.BIT16SZ;
				Array.Copy (f.stat, 0, pkt, pp, f.stat.Length);
				//Console.WriteLine (BitConverter.ToString (f.stat, 0));
				printPacket (pkt, "presentRstat");
				pp += (uint)f.stat.Length;
				break;
			}
			if(size != pp)
				return 0;
			return size;
		}

		public Dir convM2D(Byte[] stat, uint pp)
		{
			Dir d;
			
			d = new Dir();

			if(stat.Length < (int)proto.STATFIXLEN)
				return d;
			
			pp += (uint)proto.BIT16SZ;
			d.type = getushort(stat, pp);
			pp += (uint)proto.BIT16SZ;
			d.dev = getuint(stat, pp);
			pp += (uint)proto.BIT32SZ;
			d.qid = getqid(stat, pp);
			pp += (uint)proto.QIDSZ;
			d.mode = getuint(stat, pp);
			pp += (uint)proto.BIT32SZ;
			d.atime = getuint(stat, pp);
			pp += (uint)proto.BIT32SZ;
			d.mtime = getuint(stat, pp);
			pp += (uint)proto.BIT32SZ;
			d.length = getulong(stat, pp);
			pp += (uint)proto.BIT64SZ;
			d.name = getstring(stat, pp);
			pp += (uint)proto.BIT16SZ + (uint)d.name.Length;
			d.uid = getstring(stat, pp);
			pp += (uint)proto.BIT16SZ + (uint)d.uid.Length;
			d.gid = getstring(stat, pp);
			pp += (uint)proto.BIT16SZ + (uint)d.gid.Length;
			d.muid = getstring(stat, pp);
			pp += (uint)proto.BIT16SZ + (uint)d.muid.Length;

			d.status = 1;
			return d;
		}
		
		public uint sizeD2M(Dir d)
		{
			return (uint)proto.STATFIXLEN + (uint)d.name.Length + (uint)d.uid.Length +
					(uint)d.gid.Length + (uint)d.muid.Length;
		}
		
		public uint convD2M(Dir d, Byte[] stat)
		{
			uint pp, len;

			pp = 0;
			len = sizeD2M(d);

			if(len > stat.Length)
				return 0;
			
			putushort(stat, pp, (ushort)(len - (uint)proto.BIT16SZ));
			pp += (uint)proto.BIT16SZ;
			putushort(stat, pp, d.type);
			pp += (uint)proto.BIT16SZ;
			putuint(stat, pp, d.dev);
			pp += (uint)proto.BIT32SZ;
			stat[pp] = d.qid.type;
			pp += (uint)proto.BIT8SZ;
			putuint(stat, pp, d.qid.vers);
			pp += (uint)proto.BIT32SZ;
			putulong(stat, pp, d.qid.path);
			pp += (uint)proto.BIT64SZ;
			putuint(stat, pp, d.mode);
			pp += (uint)proto.BIT32SZ;
			putuint(stat, pp, d.atime);
			pp += (uint)proto.BIT32SZ;
			putuint(stat, pp, d.mtime);
			pp += (uint)proto.BIT32SZ;
			putulong(stat, pp, d.length);
			pp += (uint)proto.BIT64SZ;
			putstring(stat, pp, d.name);
			pp += (uint)proto.BIT16SZ + (uint)d.name.Length;
			putstring(stat, pp, d.uid);
			pp += (uint)proto.BIT16SZ + (uint)d.uid.Length;
			putstring(stat, pp, d.gid);
			pp += (uint)proto.BIT16SZ + (uint)d.gid.Length;
			putstring(stat, pp, d.muid);
			pp += (uint)proto.BIT16SZ + (uint)d.muid.Length;

			if(len != pp)
				return 0;
				
			return pp;
		}

		public Dir[] dols(Byte[] pkt)
		{
			Dir[] ret;
			uint pp, i;

			pp = 0;
			i = 0;

			for(i = 0, pp = 0; pp < pkt.Length; i++)
				pp += getushort(pkt, pp) + (uint)proto.BIT16SZ;

			ret = new Dir[i];
			i = 0;
			pp = 0;
			for(i = 0, pp = 0; pp < pkt.Length; i++) {
				ret[i] = convM2D(pkt, pp);
				pp += getushort(pkt, pp) + (uint)proto.BIT16SZ;
			}
			
			return ret;
		}

		public void dofid()
		{
			int cfid;

			doTclunk(cwd);
			cfid = cwd;
			cwd = fid;
			fid = cfid;
		}

		public void do9pT()
		{
			convS2M(fT, pktT);
			send9pmsg(pktT);
			pktR = read9pmsg();
			fR = convM2S(pktR);
		}

		public void do9pR()
		{
			convS2M(fR, pktR);
			send9pmsg(pktR);
		}

		public void doRversion()
		{
			fR.type = (byte)proto.Rversion;
			fR.tag = 65535;
			fR.msize = mmsgsz;
			fR.version = "9P2000";
			do9pR();
			if(fR.type == (sbyte)proto.Rerror)
				throw new ninepexception("Error on Rversion");

			if(fR.msize < mmsgsz) {
				mmsgsz = fR.msize;
				mdatasz = fR.msize + (uint)proto.IOHDRSIZE;
			}
		}
		public void doTversion()
		{
			fT.type = (byte)proto.Tversion;
			fT.tag = 65535;
			fT.msize = mmsgsz;
			fT.version = "9P2000";
			do9pT();
			if(fR.type == (sbyte)proto.Rerror)
				throw new ninepexception("Error on Rversion");

			if(fR.msize < mmsgsz) {
				mmsgsz = fR.msize;
				mdatasz = fR.msize + (uint)proto.IOHDRSIZE;
			}
		}

		public void doRerror(ushort tag, string msg){
			fR.type = (byte)proto.Rerror;
			fR.tag = tag;
			fR.ename = msg;
			do9pR ();
		}
		public void doTauth()
		{
			fT.type = (byte)proto.Tauth;
			fT.tag = ++tag;
			fT.afid = afid;
			fT.uname = uname;
			fT.aname = aname;
			do9pT();
			if(fR.type == (sbyte)proto.Rauth)
				throw new ninepexception("Error, auth not supported for now");
		}
		
		public void doTattach()
		{
			fT.type = (byte)proto.Tattach;
			fT.tag = ++tag;
			fT.fid = root;
			fT.afid = afid;
			fT.uname = uname;
			fT.aname = aname;
			do9pT();
			if(fR.type == (sbyte)proto.Rerror)
				throw new ninepexception("Error, attach failed");
		}
		public void doRattach(Qid qid)
		{
			fR.type = (byte)proto.Rattach;
			fR.tag = fT.tag;
			fR.qid = qid;
			do9pR();
//			if(fR.type == (sbyte)proto.Rerror)
//				throw new ninepexception("Error, attach failed");
		}
		public void doTswalk(int fid, int newfid, string[] path)
		{
			fT.type = (byte)proto.Twalk;
			fT.tag = ++tag;
			fT.fid = fid;
			fT.newfid = newfid;
			fT.nwname = (ushort)path.Length;
			fT.wname = path;
			do9pT();
			if(fR.type == (sbyte)proto.Rerror)
				throw new ninepexception("Error, walk failed");
		}
		public void doRwalk(ushort nwqid, Qid[] wqid){
			fR.type = (byte)proto.Rwalk;
			fR.nwqid = nwqid;
			fR.wqid = wqid;
			do9pR ();
		}

		public void doTwalk(int fid, int newfid, string[] path)
		{
			uint i;
			string[] lss;
			
			for(i = 0; i <= path.Length; i += (uint)proto.MAXWELEM) {
				lss = new string[(path.Length - i > (uint)proto.MAXWELEM)
									? (uint)proto.MAXWELEM : path.Length - i];
				Array.Copy(path, i, lss, 0, lss.Length);
				doTswalk(fid, newfid, lss);
				if(fid != root && newfid != ffid)
					dofid();
			}
		}
		
		public void doTstat(int fid)
		{
			fT.type = (byte)proto.Tstat;
			fT.tag = ++tag;
			fT.fid = fid;
			do9pT();
			if(fR.type == (sbyte)proto.Rerror)
				throw new ninepexception("Error, stat failed");
			dir = convM2D(fR.stat, (uint)proto.BIT16SZ); //start after size bytes (fix?)
		}

		public void doRstat(Dir dir)
		{
			Byte[] stat = new Byte[sizeD2M (dir)];
			uint size = convD2M (dir, stat);
			//Console.WriteLine ("size={0}, stat.length={1}", size, stat.Length);
			fR.type = (byte)proto.Rstat;
			fR.tag = fT.tag;
			fR.stat = stat;
			fR.nstat = (ushort)(stat.Length);// - (int)proto.BIT16SZ);
			do9pR ();
		}
		public void doTwstat(int fid, Dir dir){
			int len = (int)sizeD2M (dir) - (int)proto.BIT16SZ;
			Byte[] stat = new Byte[len];
			//Console.WriteLine ("stat.length={0}", stat.Length);
			convD2M (dir, stat);
			//Console.WriteLine(BitConverter.ToString(stat));
			fT.type = (byte)proto.Twstat;
			fT.stat = stat;
			fT.tag = ++tag;
			fT.fid = fid;
			fT.nstat = (ushort)len;
			do9pT ();
		}

		public void doRwstat(){
			fR.type = (byte)proto.Rwstat;
			fR.tag = fT.tag;
			do9pR();
		}

		public void doTclunk(int fid)
		{
			fT.type = (byte)proto.Tclunk;
			fT.tag = ++tag;
			fT.fid = fid;
			do9pT();
			if(fR.type == (sbyte)proto.Rerror)
				throw new ninepexception("Error, clunk failed");
		}
		public void doRclunk(int fid)
		{
			fR.type = (byte)proto.Rclunk;
			fR.fid = fid;
			fR.tag = fT.tag;
			do9pR();
			//if(fR.type == (sbyte)proto.Rerror)
				//throw new ninepexception("Error, clunk failed");
		}
		public void doTopen(int fid, byte mode)
		{
			fT.type = (byte)proto.Topen;
			fT.tag = ++tag;
			fT.fid = fid;
			fT.mode = mode;
			fT.iounit = 0;
			do9pT();
			if(fR.type == (sbyte)proto.Rerror)
				throw new ninepexception("Error, open failed");
				
			if(fR.iounit != 0) {
				mmsgsz = fR.iounit + (uint)proto.IOHDRSIZE;
				mdatasz = fR.iounit;
			}
		}
		public void doRopen(Qid qid, uint iounit){
			fR.type = (byte)proto.Ropen;
			fR.tag = fT.tag;
			fR.qid = qid;
			fR.iounit = iounit;
			do9pR ();
		}


		public void doRread(uint count, Byte[] data){
			fR.type = (byte)proto.Rread;
			fR.tag = fT.tag;
			fR.count = count;
			fR.data = data;
			do9pR ();
		}

		public void dosTread(int fid, ulong offset, uint count)
		{
			fT.type = (byte)proto.Tread;
			fT.tag = ++tag;
			fT.fid = fid;
			fT.offset = offset;
			fT.count = count;
			do9pT();
			if(fR.type == (sbyte)proto.Rerror)
				throw new ninepexception("Error, read failed");
		}
		
		public void doTread(int fid, ulong offset, uint count)
		{
			Byte[] strip;
			uint len;
			
			len = 0;
			readbuf = new Byte[count];
			
			while(len < count) {
				dosTread(fid, offset, ((count - len) > mdatasz) ? mdatasz : count);
				Array.Copy(fR.data, 0, readbuf, len, fR.data.Length);
				len += (uint)fR.data.Length;
				if(fR.data.Length != mdatasz && len < count)
					break;
			}
			
			if(len < count) {
				strip = new Byte[len];
				Array.Copy(readbuf, 0, strip, 0, len);
				readbuf = strip;
			}
		}

		public void doRwrite(uint count){
			fR.type = (byte)proto.Rwrite;
			fR.tag = fT.tag;
			fR.count = count;
			do9pR ();
		}


		public void dosTwrite(int fid, ulong offset, uint count, Byte[] data)
		{
			fT.type = (byte)proto.Twrite;
			fT.tag = ++tag;
			fT.fid = fid;
			fT.offset = offset;
			fT.count = count;
			fT.data = data;
			do9pT();
			if(fR.type == (sbyte)proto.Rerror)
				throw new ninepexception("Error, write failed");
		}

		public void doTwrite(int fid, ulong offset, uint count, Byte[] data)
		{
			Byte[] strip;
			uint len;
			
			len = 0;
			
			while(len < count) {
				strip = new Byte[((count - len) > mdatasz) ? mdatasz : count];
				Array.Copy(data, len, strip, 0, strip.Length);
					dosTwrite(fid, offset, (uint)strip.Length, strip);
				len += (uint)strip.Length;
			}
		}
		public void doTremove(int fid){
			fT.type = (byte)proto.Tremove;
			fT.tag = ++tag;
			fT.fid = fid;
			do9pT ();
		}

		public void doRremove(){
			fR.type = (byte)proto.Rremove;
			fR.tag = fT.tag;
			do9pR ();
		}

		public void doTflush(ushort oldtag){
			fT.type = (byte)proto.Tremove;
			fT.oldtag = oldtag;
			fT.tag = ++tag;
			do9pT ();
		}
		public void doRflush(){
			fR.type = (byte)proto.Rflush;
			fR.tag = fT.tag;
			do9pR ();
		}

		public void doTcreate(int fid, string name, uint perm, byte mode){
			fT.type = (byte)proto.Tcreate;
			fT.fid = fid;
			fT.name = name;
			fT.perm = perm;
			fT.mode = mode;
			do9pT ();
		}

		public void doRcreate(Qid qid, uint iounit){
			fR.type = (byte)proto.Rcreate;
			fR.tag = fT.tag;
			fR.qid = qid;
			fR.iounit = iounit;
			do9pR ();
		}
		public TcpListener serve(int port)
		{
			//IPHostEntry iphost;
			//IPAddress[] addr;
			//EndPoint ep;
			TcpListener server;

			tag = 10;
			root = 9;
			afid = -1;
			cwd = 7;
			fid = 6;
			ffid = 5;
			mmsgsz = (uint)proto.MAXPKTSIZE;
			mdatasz = mmsgsz - (uint)proto.IOHDRSIZE;

			uname = "andrey";
			aname = "";

			fT = new Fcall();
			pktR = new Byte[mmsgsz];

			//iphost = Dns.GetHostEntry(host);
			//addr = iphost.AddressList;
			server = new TcpListener (IPAddress.Any, port);
			return server;
//			sock = new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp);
//			try {
//				sock.Connect(ep);
//				Console.WriteLine("Connected");
//			} catch(Exception ex) {
//				throw new ninepexception(ex.ToString());
//			}
		}
		public void recieve(TcpClient client){
			///convS2M(fT, pktT);
			//send9pmsg(pktT);
			pktT = read9pmsg();
			//printPacket (pktT, "recieveT");
			fT = convM2S(pktT);
		}

		public TcpClient AcceptTcpClient(TcpListener serve){
			TcpClient client = serve.AcceptTcpClient ();
			sock = client.Client;
			return client;
		}
	}



}
