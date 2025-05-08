package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Configurações padrão
const (
	defaultTimeout = 500 * time.Millisecond
	defaultThreads = 100
	version        = "1.0.0"
)

// Informações do serviço por porta
var commonPorts = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	111:  "RPC",
	135:  "MSRPC",
	139:  "NetBIOS",
	143:  "IMAP",
	443:  "HTTPS",
	445:  "SMB",
	993:  "IMAPS",
	995:  "POP3S",
	1723: "PPTP",
	3306: "MySQL",
	3389: "RDP",
	5900: "VNC",
	8080: "HTTP-Proxy",
}

// Resultato de um scan de porta
type PortResult struct {
	Port    int
	State   string
	Service string
}

// Função para exibir a mensagem de ajuda personalizada
func showCustomHelp() {
	fmt.Println("Argos - Scanner de Portas TCP")
	fmt.Printf("Versão: %s\n\n", version)
	fmt.Println("USO:")
	fmt.Println("  go run argos.go [opções]")
	fmt.Println("\nOPÇÕES:")
	fmt.Println("  -host string")
	fmt.Println("        Host para escanear (obrigatório)")
	fmt.Println("  -p string")
	fmt.Println("        Range de portas para escanear (ex: 22,80,100-200) (default \"1-1024\")")
	fmt.Println("  -t int")
	fmt.Printf("        Número de threads concorrentes (default %d)\n", defaultThreads)
	fmt.Println("  -timeout int")
	fmt.Printf("        Timeout em milissegundos (default %d)\n", int(defaultTimeout/time.Millisecond))
	fmt.Println("  -v")
	fmt.Println("        Modo verbose - exibe mais informações")
	fmt.Println("  -4")
	fmt.Println("        Usar apenas IPv4 (default true)")
	fmt.Println("  -h, -help")
	fmt.Println("        Exibe esta mensagem de ajuda")
	fmt.Println("\nEXEMPLOS:")
	fmt.Println("  go run argos.go -host example.com")
	fmt.Println("  go run argos.go -host 192.168.1.1 -p 22,80,443 -t 50 -timeout 1000")
	fmt.Println("  go run argos.go -host scanme.nmap.org -p 1-1000 -v")
	os.Exit(0)
}

// Parser para o range de portas
func parsePortRange(portRange string) ([]int, error) {
	var ports []int

	// Se vazio, retorna lista vazia
	if portRange == "" {
		return ports, nil
	}

	ranges := strings.Split(portRange, ",")
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("formato de range inválido: %s", r)
			}

			start, err := strconv.Atoi(parts[0])
			if err != nil {
				return nil, fmt.Errorf("porta inicial inválida: %s", parts[0])
			}

			end, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, fmt.Errorf("porta final inválida: %s", parts[1])
			}

			if start > end {
				return nil, fmt.Errorf("porta inicial maior que porta final: %d > %d", start, end)
			}

			for port := start; port <= end; port++ {
				ports = append(ports, port)
			}
		} else {
			port, err := strconv.Atoi(r)
			if err != nil {
				return nil, fmt.Errorf("porta inválida: %s", r)
			}
			ports = append(ports, port)
		}
	}

	return ports, nil
}

// Verifica se o host é válido e prioriza IPv4
func validateHost(host string) (string, error) {
	// Tenta resolver o host para testar se é válido
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("não foi possível resolver o host %s: %v", host, err)
	}

	// Procura primeiro por um endereço IPv4
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	// Se não encontrou IPv4, usa o primeiro IP disponível
	if len(ips) > 0 {
		return ips[0].String(), nil
	}

	return "", fmt.Errorf("nenhum endereço IP encontrado para %s", host)
}

// Função para escanear uma porta
func scanPort(host string, port int, timeout time.Duration) PortResult {
	result := PortResult{
		Port:    port,
		State:   "closed",
		Service: "unknown",
	}

	address := fmt.Sprintf("%s:%d", host, port)

	// Tenta conectar explicitamente via TCP
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", address)

	if err == nil && conn != nil {
		defer conn.Close()
		result.State = "open"

		// Adiciona informação do serviço se conhecida
		if service, ok := commonPorts[port]; ok {
			result.Service = service
		} else {
			// Tenta identificar o serviço usando banner grabbing para portas desconhecidas
			// Definimos um timeout mais curto para leitura do banner
			readTimeout := 200 * time.Millisecond
			err := conn.SetReadDeadline(time.Now().Add(readTimeout))
			if err == nil {
				// Buffer para armazenar o banner
				buff := make([]byte, 1024)
				// Tenta ler alguns bytes para ver se há um banner
				_, err := conn.Read(buff)
				if err == nil {
					// Se conseguimos ler algo, podemos considerar um serviço personalizado
					result.Service = "custom-service"
				}
			}
		}
	} else {
		// Verifica se é filtrado (firewall) ou realmente fechado
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.State = "filtered"
		}
	}

	return result
}

func isHostAlive(host string, timeout time.Duration) bool {
	// Tenta uma conexão rápida na porta 80 ou 443 para ver se o host está online
	for _, port := range []int{80, 443} {
		address := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}

	// Tenta ping (ICMP) - não funciona em todos os ambientes devido a permissões
	// Este é um ping TCP simplificado
	cmd := exec.Command("ping", "-c", "1", "-W", "2", host)
	err := cmd.Run()
	return err == nil
}

func main() {
	// Verifica se a ajuda foi solicitada diretamente (antes de processar outros flags)
	for _, arg := range os.Args[1:] {
		if arg == "-help" || arg == "--help" || arg == "-h" {
			showCustomHelp()
			return
		}
	}

	// Configura os argumentos de linha de comando
	var (
		portRange string
		host      string
		threads   int
		timeout   int
		verbose   bool
	)

	flag.StringVar(&host, "host", "", "Host para escanear (obrigatório)")
	flag.StringVar(&portRange, "p", "1-1024", "Range de portas para escanear (ex: 22,80,100-200)")
	flag.IntVar(&threads, "t", defaultThreads, "Número de threads concorrentes")
	flag.IntVar(&timeout, "timeout", int(defaultTimeout/time.Millisecond), "Timeout em milissegundos")
	flag.BoolVar(&verbose, "v", false, "Modo verbose - exibe mais informações")
	useIPv4 := flag.Bool("4", true, "Usar apenas IPv4")

	// Configurando a flag de ajuda personalizada
	flag.Usage = showCustomHelp
	flag.Parse()

	// Verifica se o host foi fornecido
	if host == "" {
		fmt.Print("Digite o host para escanear: ")
		fmt.Scanln(&host)
	}

	// Valida e resolve o host
	resolvedIP, err := validateHost(host)
	if err != nil {
		fmt.Println("Erro:", err)
		os.Exit(1)
	}

	timeoutDuration := time.Duration(timeout) * time.Millisecond

	// Verifica se o host está online
	fmt.Printf("Verificando se %s está online...\n", host)
	if !isHostAlive(resolvedIP, timeoutDuration*2) {
		fmt.Printf("Aviso: %s (%s) parece estar offline ou inacessível.\n", host, resolvedIP)
		fmt.Println("Continuando com o scan, mas resultados podem ser imprecisos.")
	} else {
		fmt.Printf("Host %s (%s) está online.\n", host, resolvedIP)
	}

	// Respeita a flag IPv4 (useIPv4)
	if *useIPv4 && !strings.Contains(resolvedIP, ".") {
		fmt.Println("Forçando uso de IPv4, mas apenas endereço IPv6 disponível. Tentando re-resolver...")
		addrs, err := net.LookupHost(host)
		if err == nil {
			for _, addr := range addrs {
				if net.ParseIP(addr).To4() != nil {
					resolvedIP = addr
					fmt.Printf("Usando endereço IPv4: %s\n", resolvedIP)
					break
				}
			}
		}
	}

	// Parse do range de portas
	ports, err := parsePortRange(portRange)
	if err != nil {
		fmt.Println("Erro no range de portas:", err)
		os.Exit(1)
	}

	// Usa 1-1024 como default se nenhuma porta for especificada
	if len(ports) == 0 {
		for i := 1; i <= 1024; i++ {
			ports = append(ports, i)
		}
	}

	// Exibe informações do scan
	fmt.Printf("\nIniciando scan em %s (%s)\n", host, resolvedIP)
	fmt.Printf("Escaneando %d portas com %d threads e timeout de %dms\n", len(ports), threads, timeout)
	fmt.Println("Iniciando scan TCP...\n")
	startTime := time.Now()

	// Configura os workers com semáforo para controlar concorrência
	var wg sync.WaitGroup
	results := make([]PortResult, 0)
	resultsChan := make(chan PortResult)
	done := make(chan bool)
	sem := make(chan struct{}, threads)

	// Goroutine para coletar resultados
	go func() {
		for result := range resultsChan {
			if result.State == "open" {
				results = append(results, result)
				if verbose {
					fmt.Printf("\rPorta %d: %s (%s)          \n", result.Port, result.State, result.Service)
				}
			} else if verbose && result.State == "filtered" {
				fmt.Printf("\rPorta %d: filtrada          \n", result.Port)
			}
		}
		done <- true
	}()

	// Inicia os scans
	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{} // Adquire um slot no semáforo

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }() // Libera o slot no semáforo

			result := scanPort(resolvedIP, p, timeoutDuration)
			resultsChan <- result
			// Exibir progresso a cada 100 portas
			if p%100 == 0 {
				fmt.Printf("\rEscaneando... %.1f%% concluído", float64(p)/float64(len(ports))*100)
			}
		}(port)
	}

	// Aguarda todos os scans terminarem
	wg.Wait()
	close(resultsChan)
	<-done

	// Ordena os resultados por porta
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	// Exibe os resultados
	fmt.Printf("\r                                                           \r") // Limpa a linha de progresso
	fmt.Println("\nPortas escaneadas:", len(ports))

	if len(results) > 0 {
		fmt.Println("\nPORTA\tESTADO\tSERVIÇO")
		fmt.Println("-----\t------\t-------")
		for _, r := range results {
			fmt.Printf("%d\t%s\t%s\n", r.Port, r.State, r.Service)
		}
	} else {
		fmt.Println("\nNenhuma porta aberta encontrada.")
		fmt.Println("\nSugestões:")
		fmt.Println("- Verifique se o host está online e acessível")
		fmt.Println("- Aumente o timeout (tente -timeout 2000)")
		fmt.Println("- Escaneie portas específicas conhecidas (-p 80,443,8080,22)")
		fmt.Println("- O host pode estar protegido por firewall")
	}

	fmt.Printf("\nScan completo em %.2f segundos\n", time.Since(startTime).Seconds())
}
