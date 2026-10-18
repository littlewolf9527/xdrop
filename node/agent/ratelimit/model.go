package ratelimit

// 测试判据用，agent 运行时不调用。 ModelTake mirrors PLAN ③-2 steps 0–6.
// State retains whole-packet tokens and a monotonic nanosecond timestamp.
type State struct{ Tokens, LastUpdate uint64 }

type Result struct {
	State            State
	Allowed          bool
	Branch           string // new / full / advance / addzero / drop
	NormalizedFuture bool
	Add              uint64
	Advance          uint64
}

const NS uint64 = 1000000000

func ModelDivisor(d uint64) uint64 {
	if d == 0 {
		return 256
	}
	if d > MaxDivisor {
		return MaxDivisor
	}
	return d
}

func ModelCapacity(rate uint32, divisor uint64) uint64 {
	d := ModelDivisor(divisor)
	return (2*uint64(rate) + d - 1) / d
}

func ModelTake(state State, now uint64, rate uint32, divisor uint64) Result {
	if rate == 0 {
		panic("ModelTake requires rate > 0")
	}
	r, d := uint64(rate), ModelDivisor(divisor)
	capacity := ModelCapacity(rate, d)
	if state.LastUpdate == 0 {
		return Result{State: State{capacity - 1, now}, Allowed: true, Branch: "new"}
	}
	out := Result{}
	// 0. Normalize future timestamps before subtracting or advancing them.
	if state.LastUpdate > now {
		state.LastUpdate = now
		out.NormalizedFuture = true
	}
	// 1. Clamp persistent tokens before adding, including arbitrary u64 values.
	if state.Tokens > capacity {
		state.Tokens = capacity
	}
	// 2. Bound elapsed by the time needed to fill this capacity.
	elapsed := now - state.LastUpdate
	capNS := (capacity*d*NS + r - 1) / r
	if elapsed > capNS {
		elapsed = capNS
	}
	// 3. Fractional rate, with all operands promoted to u64.
	add := elapsed * r / (d * NS)
	out.Add = add
	// 4. Clamp the replenished bucket.
	tokens := state.Tokens + add
	if tokens > capacity {
		tokens = capacity
	}
	// 5. Full buckets stop timing even when add == 0.
	switch {
	case tokens == capacity:
		state.LastUpdate = now
		out.Branch = "full"
	case add > 0:
		out.Advance = (add*d*NS + r - 1) / r
		state.LastUpdate += out.Advance
		out.Branch = "advance"
	case tokens > 0:
		out.Branch = "addzero"
	default:
		out.Branch = "drop"
	}
	// 6. Consume one whole-packet token if available.
	if tokens >= 1 {
		tokens--
		out.Allowed = true
	}
	state.Tokens = tokens
	out.State = state
	return out
}
