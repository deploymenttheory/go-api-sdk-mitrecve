package cve

import (
	"testing"
	"time"
)

func TestValidateCVEID(t *testing.T) {
	tests := []struct {
		name    string
		cveID   string
		wantErr bool
	}{
		{"valid CVE", "CVE-2023-1234", false},
		{"valid CVE with long sequence", "CVE-2023-123456", false},
		{"empty CVE ID", "", true},
		{"invalid format", "invalid-format", true},
		{"missing CVE prefix", "2023-1234", true},
		{"invalid year", "CVE-1998-1234", true},
		{"future year", "CVE-2101-1234", true},
		{"non-numeric year", "CVE-abcd-1234", true},
		{"non-numeric sequence", "CVE-2023-abcd", true},
		{"short sequence", "CVE-2023-123", false}, // Should be valid
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCVEID(tt.cveID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCVEID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExtractYearFromCVEID(t *testing.T) {
	tests := []struct {
		name    string
		cveID   string
		want    int
		wantErr bool
	}{
		{"valid CVE", "CVE-2023-1234", 2023, false},
		{"invalid CVE", "invalid", 0, true},
		{"valid year", "CVE-2020-5678", 2020, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractYearFromCVEID(tt.cveID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractYearFromCVEID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ExtractYearFromCVEID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractSequenceFromCVEID(t *testing.T) {
	tests := []struct {
		name    string
		cveID   string
		want    int
		wantErr bool
	}{
		{"valid CVE", "CVE-2023-1234", 1234, false},
		{"long sequence", "CVE-2023-123456", 123456, false},
		{"invalid CVE", "invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractSequenceFromCVEID(tt.cveID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractSequenceFromCVEID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ExtractSequenceFromCVEID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatCVEID(t *testing.T) {
	tests := []struct {
		name     string
		year     int
		sequence int
		want     string
	}{
		{"short sequence", 2023, 1234, "CVE-2023-1234"},
		{"long sequence", 2023, 123456, "CVE-2023-123456"},
		{"minimum sequence", 2023, 1, "CVE-2023-0001"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatCVEID(tt.year, tt.sequence); got != tt.want {
				t.Errorf("FormatCVEID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidCVEState(t *testing.T) {
	tests := []struct {
		name  string
		state CVEState
		want  bool
	}{
		{"reserved", CVEStateReserved, true},
		{"published", CVEStatePublished, true},
		{"rejected", CVEStateRejected, true},
		{"invalid", CVEState("INVALID"), false},
		{"empty", CVEState(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidCVEState(tt.state); got != tt.want {
				t.Errorf("IsValidCVEState() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCVEState(t *testing.T) {
	tests := []struct {
		name     string
		stateStr string
		want     CVEState
		wantErr  bool
	}{
		{"reserved", "reserved", CVEStateReserved, false},
		{"PUBLISHED", "PUBLISHED", CVEStatePublished, false},
		{"rejected", "rejected", CVEStateRejected, false},
		{"invalid", "invalid", "", true},
		{"empty", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCVEState(tt.stateStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCVEState() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseCVEState() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetCurrentCVEYear(t *testing.T) {
	currentYear := time.Now().Year()
	got := GetCurrentCVEYear()
	if got != currentYear {
		t.Errorf("GetCurrentCVEYear() = %v, want %v", got, currentYear)
	}
}

func TestIsRecentCVE(t *testing.T) {
	now := time.Now()
	recentDate := now.AddDate(0, 0, -5)    // 5 days ago
	oldDate := now.AddDate(0, 0, -15)      // 15 days ago

	tests := []struct {
		name string
		cve  *CVERecord
		days int
		want bool
	}{
		{
			name: "recent CVE",
			cve: &CVERecord{
				CVEMetadata: CVEMetadata{
					DatePublished: &recentDate,
				},
			},
			days: 10,
			want: true,
		},
		{
			name: "old CVE",
			cve: &CVERecord{
				CVEMetadata: CVEMetadata{
					DatePublished: &oldDate,
				},
			},
			days: 10,
			want: false,
		},
		{
			name: "no published date",
			cve: &CVERecord{
				CVEMetadata: CVEMetadata{
					DatePublished: nil,
				},
			},
			days: 10,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRecentCVE(tt.cve, tt.days); got != tt.want {
				t.Errorf("IsRecentCVE() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetPrimaryDescription(t *testing.T) {
	tests := []struct {
		name string
		cve  *CVERecord
		want string
	}{
		{
			name: "English description",
			cve: &CVERecord{
				Containers: Containers{
					CNA: &CNAContainer{
						Descriptions: []Description{
							{Lang: "en", Value: "English description"},
							{Lang: "fr", Value: "French description"},
						},
					},
				},
			},
			want: "English description",
		},
		{
			name: "No English, return first",
			cve: &CVERecord{
				Containers: Containers{
					CNA: &CNAContainer{
						Descriptions: []Description{
							{Lang: "fr", Value: "French description"},
							{Lang: "es", Value: "Spanish description"},
						},
					},
				},
			},
			want: "French description",
		},
		{
			name: "No CNA container",
			cve: &CVERecord{
				Containers: Containers{
					CNA: nil,
				},
			},
			want: "",
		},
		{
			name: "No descriptions",
			cve: &CVERecord{
				Containers: Containers{
					CNA: &CNAContainer{
						Descriptions: []Description{},
					},
				},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetPrimaryDescription(tt.cve); got != tt.want {
				t.Errorf("GetPrimaryDescription() = %v, want %v", got, tt.want)
			}
		})
	}
}