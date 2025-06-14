package prom

import (
	"os"
	"path/filepath"
)

const (
	TextFileDir  = "/etc/prometheus/node_exporter/textfile_collector"
	TextFileName = "linkspeed.prometheus"
)

func AppendMetric(metric string, value string, tags map[string]string) error {
	if len(metric) == 0 || len(value) == 0 {
		return nil // No metric or value to write
	}
	str := metric
	if len(tags) > 0 {
		str += "{" + FormatTags(tags) + "}"
	}
	str += " " + value + "\n"
	file, err := os.OpenFile(filepath.Join(TextFileDir, TextFileName), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
