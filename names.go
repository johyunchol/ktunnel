package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var adjectives = []string{
	"amber", "brave", "bright", "calm", "clever", "cobalt", "cosmic", "crimson",
	"eager", "frosty", "fuzzy", "gentle", "golden", "happy", "jolly", "lunar",
	"lucky", "mellow", "neat", "noble", "quiet", "rapid", "silent", "solar",
	"swift", "tidy", "vivid", "witty", "zesty",
}

var nouns = []string{
	"otter", "falcon", "panda", "maple", "cedar", "comet", "ember", "harbor",
	"lantern", "meadow", "nimbus", "orchid", "pebble", "quartz", "ripple",
	"summit", "thicket", "violet", "walrus", "zephyr", "badger", "dolphin",
	"finch", "grove", "heron",
}

const hexDigits = "0123456789abcdef"

// randomName returns a readable, collision-resistant subdomain such as
// "brave-otter-7f3a". The suffix keeps two people demoing at once from
// stepping on each other.
func randomName() (string, error) {
	adj, err := pick(adjectives)
	if err != nil {
		return "", err
	}
	noun, err := pick(nouns)
	if err != nil {
		return "", err
	}
	suffix := make([]byte, 4)
	for i := range suffix {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(hexDigits))))
		if err != nil {
			return "", err
		}
		suffix[i] = hexDigits[n.Int64()]
	}
	return fmt.Sprintf("%s-%s-%s", adj, noun, suffix), nil
}

func pick(list []string) (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(list))))
	if err != nil {
		return "", err
	}
	return list[n.Int64()], nil
}
