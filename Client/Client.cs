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
			ninepc.ninep test;
			string cmd, server;
			int i;
			uint offset;
			Dir[] dirs;
			string[] lss, lsc;
	
			test = new ninepc.ninep ();
			//server = "sources.cs.bell-labs.com";
			server = "127.0.0.1";
	
			try {
				//test.connect (server, 564);
				test.connect(server,9999);
				test.doTversion ();
				test.doTauth ();
				test.doTattach ();
				test.doTwalk (test.root, test.cwd, new string[0]);
	
				for (;;) {
					Console.Write ("{0}% ", server);
					cmd = Console.ReadLine ();
	
					if (cmd.StartsWith ("ls")) {
						test.doTwalk (test.cwd, test.ffid, new string[] { "." });
						//printPacket (test.pktR, "R");
						test.doTopen (test.ffid, 0x00);
						//printPacket (test.pktR, "R");
						test.doTread (test.ffid, 0, (uint)test.mdatasz);
						//printPacket (test.pktR, "R");
						//printPacket (test.pktT, "T");
						//printPacket (test.pktR, "R");
						dirs = test.dols (test.readbuf);
						foreach (Dir d in dirs)
							Console.WriteLine ("{0} {1} {2} {3} {4}", test.modestr (d.mode), d.uid,
								d.gid, d.length, d.name);
						test.doTclunk (test.ffid);
						continue;
					}
	
					if (cmd.StartsWith ("cd")) {
						lss = cmd.Split (" ".ToCharArray ());
						if (lss.Length < 2)
							continue;
						lsc = lss [1].Split ("/".ToCharArray ());
						test.doTwalk (test.cwd, test.fid, lsc);
						continue;
					}
	
					if (cmd.StartsWith ("cat")) {
						lss = cmd.Split (" ".ToCharArray ());
						Array.Copy (lss, 1, lss, 0, lss.Length - 1);
						for (i = 0; i < (lss.Length - 1); i++) {
							offset = 0;
							test.doTwalk (test.cwd, test.ffid, new string[] { lss [i] });
							test.doTstat (test.ffid);
							test.doTopen (test.ffid, 0x00);
							test.doTread (test.ffid, offset, (uint)test.dir.length);
							Console.WriteLine (test.convstring (test.readbuf));
							test.doTclunk (test.ffid);
						}
					}
	
					if (cmd.StartsWith ("rm")) {
						lss = cmd.Split (" ".ToCharArray ());
						Array.Copy (lss, 1, lss, 0, lss.Length - 1);
						for (i = 0; i < (lss.Length - 1); i++) {
							offset = 0;
							test.doTwalk (test.cwd, test.ffid, new string[] { lss [i] });
							test.doTremove(test.ffid);
						}
					}
					if (cmd.StartsWith ("touch")) {
						lss = cmd.Split (" ".ToCharArray ());
						Array.Copy (lss, 1, lss, 0, lss.Length - 1);
						for (i = 0; i < (lss.Length - 1); i++) {
							offset = 0;
							test.doTcreate(test.cwd, lss[i], 0x0777, (byte)proto.ORDWR);
						}
					}
					if (cmd.StartsWith ("mkdir")) {
						lss = cmd.Split (" ".ToCharArray ());
						Array.Copy (lss, 1, lss, 0, lss.Length - 1);
						for (i = 0; i < (lss.Length - 1); i++) {
							offset = 0;
							test.doTcreate(test.cwd, lss[i], 0x00000777 | (uint)proto.DMDIR, (byte)proto.OREAD);
						}
					}
					if(cmd.StartsWith("wstat")){
						lss = cmd.Split (" ".ToCharArray ());
						//Array.Copy (lss, 1, lss, 0, lss.Length - 1);
						Array.ForEach(lss, x => Console.WriteLine(x));
						test.doTwalk (test.cwd, test.ffid, new string[] { lss [1] });
						Inode node = createnode(lss[2],0x00000777, lss[3], lss[4], (byte)proto.QTFILE);
						node.dir.length = 0;
						Console.WriteLine ("{0} {1} {2} {3} {4}", test.modestr (node.dir.mode), node.dir.uid,
							node.dir.gid, node.dir.length, node.dir.name);
						test.doTwstat(test.ffid, node.dir);
						test.doTclunk(test.ffid);
					}
					if (cmd.StartsWith ("q"))
						break;
				}
	
				test.doTclunk (test.cwd);
				test.doTclunk (test.root);
	
				test.shutdown ();
			} catch (Exception ex) {
				Console.WriteLine ("Error main: {0}", ex.ToString ());
			}	
		}
	 }
}

