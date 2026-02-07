// Package output demonstrates modern output formatting patterns
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

// Result represents a scan result
type Result struct {
	Host    string `json:"host" csv:"host"`
	Port    int    `json:"port" csv:"port"`
	State   string `json:"state" csv:"state"`
	Service string `json:"service" csv:"service"`
	Version string `json:"version,omitempty" csv:"version"`
}

// Formatter handles different output formats
type Formatter struct {
	format string
	color  bool
	writer io.Writer
}

// NewFormatter creates a new formatter
func NewFormatter(format string, color bool, w io.Writer) *Formatter {
	return &Formatter{
		format: format,
		color:  color,
		writer: w,
	}
}

// Format outputs the results in the specified format
func (f *Formatter) Format(results []Result) error {
	switch f.format {
	case "json":
		return f.formatJSON(results)
	case "csv":
		return f.formatCSV(results)
	case "table":
		return f.formatTable(results)
	default:
		return fmt.Errorf("unknown format: %s", f.format)
	}
}

func (f *Formatter) formatJSON(results []Result) error {
	encoder := json.NewEncoder(f.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

func (f *Formatter) formatCSV(results []Result) error {
	if len(results) == 0 {
		return nil
	}

	writer := csv.NewWriter(f.writer)
	defer writer.Flush()

	// Header
	if err := writer.Write([]string{"Host", "Port", "State", "Service", "Version"}); err != nil {
		return err
	}

	// Data
	for _, r := range results {
		row := []string{
			r.Host,
			fmt.Sprintf("%d", r.Port),
			r.State,
			r.Service,
			r.Version,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func (f *Formatter) formatTable(results []Result) error {
	if len(results) == 0 {
		fmt.Fprintln(f.writer, "No results found")
		return nil
	}

	// Lipgloss styles
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#7D56F4")).
		Padding(0, 1)

	cellStyle := lipgloss.NewStyle().Padding(0, 1)

	// Color-coded state styles
	openStyle := cellStyle.Foreground(lipgloss.Color("#04B575"))
	closedStyle := cellStyle.Foreground(lipgloss.Color("#FF6B6B"))
	filteredStyle := cellStyle.Foreground(lipgloss.Color("#FFD93D"))

	// Build rows
	rows := make([][]string, len(results))
	for i, r := range results {
		rows[i] = []string{
			r.Host,
			fmt.Sprintf("%d", r.Port),
			r.State,
			r.Service,
			r.Version,
		}
	}

	// Style function
	styleFunc := func(row, col int) lipgloss.Style {
		if row == 0 {
			return headerStyle
		}

		if !f.color {
			return cellStyle
		}

		// Color by state (column 2)
		if col == 2 {
			state := rows[row-1][2]
			switch strings.ToLower(state) {
			case "open":
				return openStyle
			case "closed":
				return closedStyle
			case "filtered":
				return filteredStyle
			}
		}
		return cellStyle
	}

	t := table.New().
		Border(lipgloss.NormalBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4"))).
		Headers("HOST", "PORT", "STATE", "SERVICE", "VERSION").
		Rows(rows...).
		StyleFunc(styleFunc)

	fmt.Fprintln(f.writer, t.Render())
	fmt.Fprintf(f.writer, "\nTotal: %d ports scanned\n", len(results))

	return nil
}
