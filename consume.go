package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Shopify/sarama"
)

type interval struct {
	start int64
	end   int64
}

type consumeConfig struct {
	topic   string
	brokers []string
	offsets map[int32]interval
	timeout time.Duration
	args    struct {
		topic   string
		brokers string
		timeout time.Duration
		offsets string
	}
}

func print(msg *sarama.ConsumerMessage) {
	fmt.Printf(
		`{"partition":%v,"offset":%v,"key":%#v,"message":%#v}
`,
		msg.Partition,
		msg.Offset,
		string(msg.Key),
		string(msg.Value),
	)
}

func parseOffsets(str string) (map[int32]interval, error) {
	if len(str) == 0 { // everything when omitted
		return map[int32]interval{-1: {sarama.OffsetOldest, 0}}, nil
	}

	result := map[int32]interval{}

	partitions := strings.Split(str, ",")
	for _, partition := range partitions {
		if len(partition) == 0 {
			continue
		}
		if strings.Count(partition, "-") > 3 {
			return result, fmt.Errorf("Invalid offsets definition: %s.", partition)
		}
		if strings.Count(partition, ":") > 1 {
			return result, fmt.Errorf("Invalid offsets definition: %s.", partition)
		}

		partition = strings.TrimSuffix(partition, ":")
		// 0
		// 0:
		// -1
		// -1-
		if !strings.Contains(partition, ":") {
			if strings.Count(partition, "-") == 1 {
				p, err := strconv.Atoi(partition)
				if err != nil {
					return result, fmt.Errorf("Invalid offsets definition: %s.", partition)
				}
				result[-1] = interval{sarama.OffsetOldest, -int64(p)}
				continue
			}

			if strings.Count(partition, "-") == 2 {
				start, err := strconv.Atoi(partition[:strings.LastIndex(partition, "-")])
				if err != nil {
					return result, fmt.Errorf("Invalid offsets definition: %s.", partition)
				}

				end := 0
				if strings.LastIndex(partition, "-")+1 < len(partition) {
					end, err = strconv.Atoi(partition[strings.LastIndex(partition, "-")+1:])
					if err != nil {
						return result, fmt.Errorf("Invalid offsets definition: %s.", partition)
					}
				}

				result[-1] = interval{int64(start), int64(end)}
				continue
			}

			p, err := strconv.Atoi(partition)
			if err != nil {
				return result, fmt.Errorf("Invalid offsets definition: %s.", partition)
			}

			result[int32(p)] = interval{sarama.OffsetOldest, 0}
			continue
		}

		// 0:1
		// 0:1-
		// 0:1-2
		// 0:-2
		// 0:-1-
		// -1:-1-
		p, err := strconv.Atoi(partition[:strings.Index(partition, ":")])
		if err != nil {
			return result, fmt.Errorf("Invalid offsets definition: %s.", partition)
		}

		i := interval{sarama.OffsetOldest, 0}
		start := partition[strings.Index(partition, ":")+1:]
		end := ""
		if strings.Contains(start, "-") {
			end = start[strings.LastIndex(start, "-")+1:]
			start = start[:strings.LastIndex(start, "-")]
		}

		if len(start) > 0 {
			s, err := strconv.Atoi(start)
			if err != nil {
				return result, fmt.Errorf("Invalid offsets definition: %s.", partition)
			}
			i.start = int64(s)
		}

		if len(end) > 0 {
			e, err := strconv.Atoi(end)
			if err != nil {
				return result, fmt.Errorf("Invalid offsets definition: %s.", partition)
			}
			i.end = int64(e)
		}

		result[int32(p)] = i
	}

	return result, nil
}

func failStartup(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	fmt.Fprintln(os.Stderr, "Use \"kt consume -help\" for more information.")
	os.Exit(1)
}

func consumeParseArgs(f *flag.FlagSet) func([]string) {
	return func(args []string) {
		var err error

		if len(args) == 0 {
			f.Usage()
		}

		f.Parse(args)

		if config.consume.args.topic == "" {
			failStartup("Topic name is required.")
		}
		config.consume.topic = config.consume.args.topic

		config.consume.brokers = strings.Split(config.consume.args.brokers, ",")
		for i, b := range config.consume.brokers {
			if !strings.Contains(b, ":") {
				config.consume.brokers[i] = b + ":9092"
			}
		}

		config.consume.offsets, err = parseOffsets(config.consume.args.offsets)
		if err != nil {
			failStartup(fmt.Sprintf("%s", err))
		}
	}
}

func consumeUsage(f *flag.FlagSet) func() {
	return func() {
		fmt.Fprintln(os.Stderr, "Usage of consume:")
		f.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Offsets can be specified as a comma-separated list of intervals:

  partition1:start-end,partition2:start-end

Examples:

To consume messages from partition 0 between offsets 10 and 20 (inclusive).

  0:10-20

To define an interval for all partitions use -1 as the partition identifier:

  -1:2-10

Short version to consume messages from all partitions until offset 10:

  -10

To consume from multiple partitions:

  0:4-,2:1-10,6

This would consume messages from three partitions:

  - Anything from partition 0 starting at offset 4.
  - Messages between offsets 1 and 10 from partition 2.
  - Anything from partition 6.
`)
		os.Exit(2)
	}
}

func consumeCommand() command {
	flags := flag.NewFlagSet("consume", flag.ExitOnError)
	flags.StringVar(&config.consume.args.topic, "topic", "", "Topic to consume (required).")
	flags.StringVar(&config.consume.args.brokers, "brokers", "localhost:9092", "Comma separated list of brokers. Port defaults to 9092 when omitted.")
	flags.StringVar(&config.consume.args.offsets, "offsets", "", "Specifies what messages to read by partition and offset range (defaults to all).")
	flags.DurationVar(&config.consume.timeout, "timeout", time.Duration(0), "Timeout after not reading messages (default 0 to disable).")

	flags.Usage = consumeUsage(flags)

	return command{
		flags:     flags,
		parseArgs: consumeParseArgs(flags),

		run: func(closer chan struct{}) {

			consumer, err := sarama.NewConsumer(config.consume.brokers, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to create consumer err=%v\n", err)
				os.Exit(1)
			}
			defer consumer.Close()

			partitions := findPartitions(consumer, config.consume)
			if len(partitions) == 0 {
				fmt.Fprintf(os.Stderr, "Found no partitions to consume.\n")
				os.Exit(1)
			}

			consume(config.consume, closer, consumer, partitions)
		},
	}
}

func consume(
	config consumeConfig,
	closer chan struct{},
	consumer sarama.Consumer,
	partitions []int32,
) {
	var wg sync.WaitGroup
consuming:
	for _, partition := range partitions {
		offsets, ok := config.offsets[partition]
		if !ok {
			offsets, ok = config.offsets[-1]
		}
		partitionConsumer, err := consumer.ConsumePartition(
			config.topic,
			partition,
			offsets.start,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to consume partition %v err=%v\n", partition, err)
			continue consuming
		}

		wg.Add(1)
		go consumePartition(&wg, closer, partitionConsumer, partition, offsets.end)
	}

	wg.Wait()

}

func consumePartition(
	wg *sync.WaitGroup,
	closer chan struct{},
	pc sarama.PartitionConsumer,
	p int32,
	end int64,
) {
	for {
		timeout := make(<-chan time.Time)
		if config.consume.timeout > 0 {
			timeout = time.After(config.consume.timeout)
		}

		select {
		case <-timeout:
			log.Printf("Consuming from partition [%v] timed out.", p)
			pc.Close()
			wg.Done()
			return
		case <-closer:
			pc.Close()
			wg.Done()
			return
		case msg, ok := <-pc.Messages():
			if ok {
				print(msg)
			}
			if end > 0 && msg.Offset >= end {
				pc.Close()
				wg.Done()
				return
			}
		}
	}
}

func findPartitions(consumer sarama.Consumer, config consumeConfig) []int32 {
	allPartitions, err := consumer.Partitions(config.topic)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read partitions for topic %v err=%v\n", config.topic, err)
		os.Exit(1)
	}

	_, hasDefaultOffset := config.offsets[-1]
	partitions := []int32{}
	if !hasDefaultOffset {
		for _, p := range allPartitions {
			_, ok := config.offsets[p]
			if ok {
				partitions = append(partitions, p)
			}
		}
	} else {
		partitions = allPartitions
	}

	return partitions
}
