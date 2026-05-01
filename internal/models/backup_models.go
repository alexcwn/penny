package models

type BackupTable struct {
	Columns  []string `json:"columns"`
	RowCount int      `json:"row_count"`
}

type BackupMeta struct {
	Hostname  string `json:"hostname"`
	Timestamp string `json:"timestamp"`
	Version   string `json:"version"`
	Nodes     string `json:"nodes"`
	Links     string `json:"links"`
	Variables string `json:"variables"`
}

type BackupDump struct {
	Meta   BackupMeta             `json:"meta"`
	Tables map[string]BackupTable `json:"tables"`
	DBPath string                 `json:"-"`
}
