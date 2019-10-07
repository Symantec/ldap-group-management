package main

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v2"
)

func writeConfig(filename string, config *AppConfigFile) error {
	fileBytes, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	//log.Printf("filebytes=%s", string(fileBytes))
	return ioutil.WriteFile(filename, fileBytes, 0644)
}

func TestLoadConfigFileBase(t *testing.T) {
	dir, err := ioutil.TempDir("", "config_testing")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) // clean up
	//dir := "/tmp"
	configFilename := filepath.Join(dir, "config-test.yml")
	log.Printf("New config filaneme=%s", configFilename)
	//prepare secrets file
	secretsFilename := filepath.Join(dir, "sharedSecrets.txt")
	secretsText := "supersecret\n"
	err = ioutil.WriteFile(secretsFilename, []byte(secretsText), 0644)
	if err != nil {
		t.Fatal(err)
	}
	///now we fabricate a config
	appConfig := AppConfigFile{}
	appConfig.Base.TemplatesPath = dir
	appConfig.Base.StorageURL = "sqlite:" + filepath.Join(dir, "demodb.sqlite")
	appConfig.Base.ClusterSharedSecretFilename = secretsFilename
	err = writeConfig(configFilename, &appConfig)
	if err != nil {
		t.Fatal(err)
	}

	loadedConfig, err := loadConfig(configFilename)
	if err != nil {
		log.Printf("loadConfig fail, filename=%s err=%s", configFilename, err)
		t.Fatal(err)
	}
	if len(loadedConfig.Config.Base.SharedSecrets) != 1 {
		t.Fatal("invalid number of shared secrets")
	}

}
