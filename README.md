# SynackfloodV2
Synackflood

#Command:
go build -o gorawflood main.go

sudo ./gorawflood -t 192.168.1.100 -i wlan0 -m syn -w 12 -p 443


​1. Mode Serangan Multi-Vektor (-m)
​Anda sekarang bisa mengubah target pengujian mitigasi firewall Anda ke beberapa skenario gangguan protokol yang berbeda:
​syn: Mengirim paket inisiasi koneksi. Berguna untuk menguji ketahanan kapasitas memori SYN-Received Backlog milik target.
​synack: (Bawaan awal) Mengirim paket respons palsu untuk membingungkan status state mesin target.
​rst: Mengirim instruksi pemutusan hubungan paksa. Jika port target tepat, ini bisa memutuskan sesi komunikasi aktif client asli yang sedang terhubung ke server.
​xmas: Mengaktifkan flag FIN, PSH, dan URG sekaligus. Paket ini tidak standar, memaksa sistem operasi target atau Deep Packet Inspection (DPI) pada firewall bekerja ekstra keras menganalisis paket tak beraturan ini.
