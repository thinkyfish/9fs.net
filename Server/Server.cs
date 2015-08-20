using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Collections.Generic;
using ninepc;
namespace fs.net
{
	class MainClass
	{
		public static ulong path = 0;
		public static Dictionary<int, Inode> fidlist = new Dictionary<int, Inode>();

		public static void printPacket(Byte[] pkt, string type){
			int size = (int)BitConverter.ToUInt32(pkt, 0);
			//Console.WriteLine (type + "|" + Encoding.Default.GetString (pkt,0,size));
			switch (pkt[4]){
			case (byte)proto.Twalk: type = "Twalk";	break;
			case (byte)proto.Rwalk: type = "Rwalk";	break;
			case (byte)proto.Tauth:	type = "Tauth";	break;
			case (byte)proto.Tattach:	type = "Tattach";	break;
			case (byte)proto.Topen:	type = "Topen";	break;
			case (byte)proto.Ropen:	type = "Ropen";	break;
			case (byte)proto.Tversion:	type = "Tversion"; break;
			case (byte)proto.Rversion:	type = "Rversion"; break;
			case (byte)proto.Tread:	type = "Tread";	break;
			case (byte)proto.Rread:	type = "Rread";	break;
			case (byte)proto.Rerror: type = "Rerror"; break;
			case (byte)proto.Tclunk: type = "Tclunk"; break;
			case (byte)proto.Rclunk: type = "Rclunk"; break;
			case (byte)proto.Tstat: type = "Tstat";	break;
			case (byte)proto.Rstat: type = "Rstat";	break;
			case (byte)proto.Twstat: type = "Twstat";	break;
			case (byte)proto.Rwstat: type = "Rwstat";	break;
			case (byte)proto.Tcreate:	type = "Tcreate";	break;
			case (byte)proto.Rcreate:	type = "Rcreate";	break;
			case (byte)proto.Tremove:	type = "Tremove";	break;
			case (byte)proto.Rremove:	type = "Rremove";	break;

			}
			string str = Encoding.Default.GetString (pkt, 0, size);
			char[] arr = str.ToCharArray();



			arr = Array.FindAll<char>(arr, (c => (char.IsLetterOrDigit(c) 
				|| char.IsWhiteSpace(c) 
				|| char.IsPunctuation(c)
				|| c == '-')));
			string s = new string(arr);
			Console.WriteLine( type + "|" + s);
			Console.WriteLine (type + "|" + BitConverter.ToString (pkt,0,size));
		}
		public static void printfidlist(){
			foreach( KeyValuePair<int, Inode> i in fidlist){
				Console.WriteLine("key = {0}, value = {1}", i.Key, i.Value.dir.name);
			}
		}


		public class Inode{
			public Dir dir;
			public Inode parent;
			public List<Inode> children = new List<Inode>();
			public uint mode;
			public Byte[] data;
		} 

		public  static Inode createnode(string name, uint mode, string uid, string gid, byte type)
		{
			Inode node = new Inode();
			node.dir.qid = new Qid();
			node.dir.qid.path = ++path;
			node.dir.qid.vers = 0;
			node.dir.qid.type = type;
			node.dir.name = name;
			node.dir.atime = (uint)DateTime.Now.ToFileTime();
			node.dir.mtime = node.dir.atime;
			node.dir.uid = uid;
			node.dir.gid =  gid;
			node.dir.muid = uid;
			node.dir.mode = mode;
			node.dir.status = 0;
			node.dir.type = 0;
			node.dir.dev = 0;
			node.dir.length = 0;
			return node;

		}
		public static bool delnode(Inode parent, string name){
			if (parent != null) {
				foreach (Inode c in parent.children) {
					if (c.dir.name.Equals (name)) {
						parent.children.Remove (c);
						return true;
					}
				}
			}
			return false;
		}

		public static bool walkChild(Inode cur, string name, out Inode child){
			//Console.WriteLine ("cur={0}, name={1}", cur.dir.name, name);
			if (name.Equals ("..")) {
				if (cur.dir.name.Equals ("/")) {
					child = cur;
				} else {
					child = cur.parent;
				}
				return true;
			}

			if (name.Equals (".")) {
				child = cur;
				return true;
			}

			foreach(Inode i in cur.children){
				if(i.dir.name.Equals(name)){
					child = i;
					return true;
				}
			}
			child = cur;
			return false;
		}



		public static bool listclunk(int fid){
			Inode fidnode;
			if(fidlist.TryGetValue(fid,out fidnode)){
				if((fidnode.mode & (uint)proto.ORCLOSE) > 0){
					delnode(fidnode.parent, fidnode.dir.name);
				}
				fidlist.Remove(fid);
				return true;
			}
			return false;
		}

		public static void Main(string[] args)
		{
			//SERVER CODE: if you want the client, comment until CLIENT CODE
			ninepc.ninep protocol;
			protocol = new ninepc.ninep();
			string clientname = "unset";
			//string cmd, server;
			TcpListener server = protocol.serve (9999);




			Inode root = createnode("/",0x00000755, "jeb", "kerman", (byte)proto.QTDIR);
			root.data = new Byte[0];


			Inode testdir = createnode ("testdir", 0x00000755, "jeb", "kerman", (byte)proto.QTDIR);
			testdir.data = new Byte[0];
			testdir.parent = root;
			root.children.Add (testdir);


			Qid[] wqid = new Qid[10];  //max number of walks... increase if needed.


			UTF8Encoding utf8 = new UTF8Encoding();
			Byte[] strdata = utf8.GetBytes ("This is the file contents");
			Inode child = createnode ("test", 0x00000755, "valerie", "kerman", (byte)proto.QTFILE);
			child.data = strdata;
			child.dir.length = (ulong)strdata.Length;
			child.dir.qid.vers++;
			testdir.children.Add (child);
			child.parent = testdir;


			server.Start ();
			//ep = new IPEndPoint(addr[0], port);
			while(true)
			{
				TcpClient client = protocol.AcceptTcpClient (server);
				while (client.Connected)
				{
					protocol.recieve (client);
					printPacket (protocol.pktT, "T");
					switch (protocol.fT.type) {
					case (byte)proto.Tstat:
						Inode statnode;
						if (!fidlist.TryGetValue (protocol.fT.fid, out statnode))
							protocol.doRerror (protocol.fT.tag, "unrecognized fid");
						protocol.doRstat (statnode.dir);
						break;
					case (byte)proto.Topen:
						Inode opnode;
						if (!fidlist.TryGetValue (protocol.fT.fid, out opnode))
							protocol.doRerror (protocol.fT.tag, "unrecognized fid");
						//permissions stuff goes here
						opnode.mode = protocol.fT.mode;
						protocol.doRopen (opnode.dir.qid, protocol.mmsgsz); 
						break;
					case (byte)proto.Tread:
						Inode rnode;
						uint count;
						Byte[] data;
						if (!fidlist.TryGetValue (protocol.fT.fid, out rnode)) {
							protocol.doRerror (protocol.fT.tag, "unrecognized fid");
						}
						count = protocol.fT.count;
						if (count + protocol.fT.offset > rnode.dir.length)
							count = (uint)rnode.dir.length - (uint)protocol.fT.offset;
						if (rnode.dir.qid.type == (byte)proto.QTDIR) {
							List<Byte[]> dirdata = new List<Byte[]> ();
							int len = 0;
							foreach (Inode i in rnode.children) {
								Byte[] temp = new Byte[protocol.sizeD2M (i.dir)];
								protocol.convD2M (i.dir, temp);
								//printPacket (temp, "D");
								len += temp.Length;
								dirdata.Add (temp);
							}
							data = new Byte[len];
							int pp = 0;
							foreach (Byte[] b in dirdata) {

								System.Buffer.BlockCopy (b, 0, data, pp, b.Length);
								pp += b.Length;
							}
							protocol.doRread ((uint)data.Length, data);
						} else {
							if (count > 0) {
								data = new Byte[count];
								Array.Copy (rnode.data, (int)protocol.fT.offset, data, 0, count);
								protocol.doRread (count, data);
							} else
								protocol.doRread (0, new Byte[0]);
						}
						break;
					case (byte)proto.Tauth:
						clientname = protocol.fT.uname;
						protocol.doRerror (protocol.fT.tag, "u9fs authnone: no authentication required");
						break;
					case (byte)proto.Tattach:

						if (protocol.fT.aname.Equals ("")) {
							if (fidlist.ContainsKey (protocol.fT.fid) == false) {
								fidlist.Add (protocol.fT.fid, root);
								protocol.doRattach (root.dir.qid);
							} else {
								protocol.doRerror (protocol.fT.tag, "Fid currently in use");
							}
						}
						printfidlist ();
						break;
					case (byte)proto.Tclunk:
						if (listclunk (protocol.fT.fid)) {
							Console.WriteLine ("clunked fid:{0}", protocol.fT.fid);
							protocol.doRclunk (protocol.fT.fid);
						} else {
							protocol.doRerror (protocol.fT.tag, "Unrecognized fid");
						}
						printfidlist ();
						break;
					case (byte)proto.Twalk:
						Inode cfidnode;
						Inode wfidnode;
						ushort nwqid = 0;
						if (fidlist.TryGetValue (protocol.fT.fid, out cfidnode) == false) {
							protocol.doRerror (protocol.fT.tag, "Unrecognized fid");
							break;
						} else if (fidlist.ContainsKey (protocol.fT.newfid)) {
							//protocol.doRerror (protocol.fT.tag, "New fid already in use");
							listclunk (protocol.fT.fid);
							break;
						}
						if (protocol.fT.nwname > 0) { 
							//walk throught the file tree, creating qid's
							wfidnode = cfidnode;

							for (nwqid = 0; nwqid < protocol.fT.nwname; nwqid++, cfidnode = wfidnode) {
								Console.WriteLine ("nwname={0}, wname={1}", protocol.fT.nwname, protocol.fT.wname [nwqid]);
								if (walkChild (cfidnode, protocol.fT.wname [nwqid], out wfidnode)) {
									//Console.WriteLine ("Walkchild succeeded");
									wqid [nwqid] = wfidnode.dir.qid;
								} else if (nwqid == 0) {
									protocol.doRerror (protocol.fT.tag, "first nwname walk failed");
									//Console.WriteLine ("first nwname walk failed");
									break;
								}
							}
							// take the last successful walk and make that the new fid.
							fidlist.Add (protocol.fT.newfid, wfidnode);
						} else { // simply create a new fid for the current file
							fidlist.Add (protocol.fT.newfid, cfidnode);
							nwqid = 1;
							wqid [0] = cfidnode.dir.qid;
						}
						printfidlist ();
						protocol.doRwalk (nwqid, wqid);

						break;
					case (byte)proto.Tremove:
						Inode rfidnode;
						if (fidlist.TryGetValue (protocol.fT.fid, out rfidnode) == false) {
							protocol.doRerror (protocol.fT.tag, "Unrecognized fid");
							break;
						}
						if (delnode (rfidnode.parent, rfidnode.dir.name)) {
							listclunk (protocol.fT.fid);
							protocol.doRremove ();

						}
						break;
					case (byte)proto.Tversion:
						if (protocol.fT.version.Equals ("9P2000")) {
							protocol.doRversion ();
						} else {
							protocol.doRerror (protocol.fT.tag, "Version :" + protocol.fT.version + " not supported.");
						}

						break;
					case (byte)proto.Tflush:
						//do nothing
						protocol.doRflush ();
						break;
					case (byte)proto.Tcreate:
						Inode dirnode;
						if (fidlist.TryGetValue (protocol.fT.fid, out dirnode) == false) {
							protocol.doRerror (protocol.fT.tag, "Unrecognized fid");
							break;
						}
						byte type = (byte)proto.QTFILE;
						Console.WriteLine ("perm = {0}", BitConverter.ToString ((BitConverter.GetBytes (protocol.fT.perm))));
						if ((protocol.fT.perm & (uint)proto.DMDIR) != 0) {
							type = (byte)proto.QTDIR;
							Console.WriteLine ("Created Directory");
						} 
						Inode newfile = createnode (protocol.fT.name, protocol.fT.perm, clientname, "client", type);
						dirnode.children.Add (newfile);
						newfile.parent = dirnode;
						newfile.mode = protocol.fT.mode;
						newfile.data = new Byte[0];
						protocol.doRcreate (new Qid (), protocol.mmsgsz);
						break;

					case (byte)proto.Twstat:
						Inode wnode;
						Dir tdir;
						if (fidlist.TryGetValue (protocol.fT.fid, out wnode) == false) {
							protocol.doRerror (protocol.fT.tag, "Unrecognized fid");
							break;
						}
						tdir = protocol.convM2D (protocol.fT.stat, 0);
						wnode.dir = tdir; // some permissions stuff should precede this.
						protocol.doRwstat ();
						break;

					case (byte)proto.Twrite:
						Inode wrnode;
						if (fidlist.TryGetValue (protocol.fT.fid, out wrnode) == false) {
							protocol.doRerror (protocol.fT.tag, "Unrecognized fid");
							break;
						}
						if (wrnode.mode.Equals ((uint)proto.OREAD)) {
							protocol.doRerror (protocol.fT.tag, "File not opened for writing");
							break;
						} 
						int woffset = (int)protocol.fT.offset;
						if ((wrnode.mode & (uint)proto.OAPPEND) > 0)
							woffset = (int)wrnode.data.Length;
						if (woffset > (int)wrnode.data.Length) {
							protocol.doRerror (protocol.fT.tag, "offset out of bounds");
							break;
						}
						Byte[] newdata = new Byte[woffset + (int)protocol.fT.count];
						Array.Copy (wrnode.data, 0, newdata, 0, woffset); //copy existing data before offset
						Array.Copy (protocol.fT.data, 0, newdata, woffset, protocol.fT.count);
						wrnode.data = newdata;
						wrnode.dir.muid = clientname;
						wrnode.dir.mtime = (uint)DateTime.Now.ToFileTime ();
						wrnode.dir.qid.vers += 1;
						wrnode.dir.length = (ulong)wrnode.data.Length;
						protocol.doRwrite (protocol.fT.count);
						Console.WriteLine("new contents:{0}", BitConverter.ToString (wrnode.data,0,wrnode.data.Length));
						break;

					default:
						throw new ninepexception ("unrecognized message type");
					}
					printPacket (protocol.pktR, "R");
				}
			}
		}
	}
}

