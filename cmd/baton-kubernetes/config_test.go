package main

import (
	"testing"

	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/conductorone/baton-sdk/pkg/test"
	"github.com/spf13/viper"
)

func TestConfigs(t *testing.T) {
	configurationSchema := field.NewConfiguration(
		getConfigurationFields(),
		getFieldRelationships()...,
	)

	testCases := []test.TestCase{
		// Add test cases here.
	}

	test.ExerciseTestCases(t, configurationSchema, func(v *viper.Viper) error {
		_, err := GetConfig(v)
		return err
	}, testCases)
}
