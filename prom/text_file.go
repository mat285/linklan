package prom

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	TextFileDir  = "/etc/prometheus/node_exporter/textfile_collector"
	TextFileName = "linkspeed.prom"
)

func AppendMetric(metric string, value string, ts time.Time, tags map[string]string) error {
	if true {
		return nil
	}
	// log.GetLogger(ctx).Info("Appending metric:", metric, "with value:", value, "and tags:", tags)
	if len(metric) == 0 || len(value) == 0 {
		return nil // No metric or value to writecode
	}
	str := metric
	if len(tags) > 0 {
		str += "{" + FormatTags(tags) + "}"
	}
	str += " " + value
	// if !ts.IsZero() {
	// 	str += " " + fmt.Sprintf("%d", ts.UTC().UnixMilli())
	// }
	str += "\n"
	file, err := os.OpenFile(filepath.Join(TextFileDir, fmt.Sprintf("%s-%s", time.Now().Format("2006010215150405"), TextFileName)), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteString(str); err != nil {
		return err
	}
	return nil
}

func FormatTags(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}

	tagStr := ""
	for k, v := range tags {
		tagStr += k + "=\"" + v + "\","
	}
	tagStr = tagStr[:len(tagStr)-1] // Remove trailing comma

	return tagStr
}
