package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/bls"
	blst "github.com/supranational/blst/bindings/go"
)

type PublicKey = blst.P1Affine

func hasPrefix(key *PublicKey, prefix []byte) bool {
	keyData := key.Serialize()
	return bytes.Compare(keyData[:len(prefix)], prefix) == 0
}

func searchForSeed(count *uint64, maxTries int, prefix []byte, wg *sync.WaitGroup) {
	var seed [32]byte

	for i := 0; maxTries == 0 || i < maxTries; i++ {
		_, err := rand.Read(seed[:])
		if err != nil {
			panic(err)
		}

		sk := blst.KeyGen(seed[:])
		pk := new(PublicKey).From(sk)

		hasPrefix(pk, prefix)

		if hasPrefix(pk, prefix) {
			skx := hex.EncodeToString(sk.Serialize())
			// fmt.Println("public key", hex.EncodeToString(pk.Serialize()))

			_sk := SecretKeyFromHexString("0x" + skx)
			_pk, _err := bls.PublicKeyFromSecretKey(_sk)
			if _err != nil {
				panic(_err)
			}

			pkHex := fmt.Sprintf("0x%x", bls.PublicKeyToBytes(_pk))
			if strings.HasPrefix(pkHex, "0xa") {
				fmt.Println("secret key", skx)
				fmt.Printf("%s\n\n", pkHex)
				os.Exit(0)
			}

			break
		}

		atomic.AddUint64(count, 1)
	}

	if wg != nil {
		wg.Done()
	}
}

func usage() {
	_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Usage\n%s: [options] <prefix>\n", os.Args[0])
	_, _ = fmt.Fprintf(flag.CommandLine.Output(), "<prefix> - hex of prefix (e.g. 01dead01)\n")
	_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Options:\n")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	cpu := flag.Int("cpu", 0, "num cpu to use, 0 - NumCpu Will be used")
	flag.Parse()
	if *cpu == 0 {
		*cpu = runtime.NumCPU()
	}
	if flag.NArg() != 1 {
		usage()
		return
	}
	prefixStr := flag.Arg(0)

	prefix, err := hex.DecodeString(prefixStr)
	if err != nil {
		panic(err)
	}
	if prefix[0] > 26 {
		panic("first byte should be in 0-26 range")
	}

	var count *uint64 = new(uint64)
	// start := time.Now()

	triesNeeded := new(big.Int).Exp(big.NewInt(256), big.NewInt(int64(len(prefix))), nil)
	triesNeeded.Div(triesNeeded, big.NewInt(9)) // bias because first byte may be only 0-26
	// go func() {
	// 	for {
	// 		time.Sleep(time.Second * 5)
	// 		perSec := atomic.LoadUint64(count) / uint64(time.Since(start).Seconds())

	// 		secs := new(big.Int).Div(triesNeeded, big.NewInt(int64(perSec)))

	// 		expectedWait := time.Second * time.Duration(secs.Uint64())
	// 		fmt.Println("tries per sec:", perSec, "expected wait time:", expectedWait, "time spent:", time.Since(start).Truncate(time.Second))
	// 	}
	// }()

	var wg sync.WaitGroup
	for i := 0; i < *cpu; i++ {
		wg.Add(1)
		go searchForSeed(count, 0, prefix, &wg)
	}

	wg.Wait()
}

// SecretKeyFromHexString converts a hex string to a BLS secret key
func SecretKeyFromHexString(secretKeyHex string) *bls.SecretKey {
	skBytes, err := hexutil.Decode(secretKeyHex)
	if err != nil {
		log.Fatal(err.Error())
	}

	blsSecretKey, err := bls.SecretKeyFromBytes(skBytes[:])
	if err != nil {
		log.Fatal(err.Error())
	}

	return blsSecretKey
}
