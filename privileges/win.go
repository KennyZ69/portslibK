package privileges

// on windows it does not matter because either way the tcp connect scan will be ran
func isPrivilegedWin() bool {
	return false
}
