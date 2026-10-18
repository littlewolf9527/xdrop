// dryrun checks a cold controller database without opening the source in SQLite.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/littlewolf9527/xdrop/controller/core/rules"
)

func run(args []string, out io.Writer) int {
	flags := flag.NewFlagSet("dryrun", flag.ContinueOnError)
	flags.SetOutput(out)
	path := flags.String("db", "", "cold database path (stop the controller first; active files are not a consistent snapshot)")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *path == "" || flags.NArg() != 0 {
		fmt.Fprintln(out, "usage: dryrun -db <cold database path>")
		return 2
	}
	return rules.DryRun(*path, out)
}

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }
