// Package pipeline orchestrates an ordered sequence of processing stages.
package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/netcap/netcap/internal/config"
)

// Stage represents a single processing stage in the pipeline.
type Stage interface {
	// Name returns a human-readable identifier for this stage.
	Name() string
	// Start begins the stage's work. It should respect ctx for cancellation.
	Start(ctx context.Context) error
	// Stop gracefully shuts down the stage.
	Stop(ctx context.Context) error
}

// Pipeline manages the lifecycle of an ordered list of stages.
type Pipeline struct {
	cfg    *config.Config
	logger *slog.Logger
	stages []Stage
	mu     sync.Mutex
}

// New creates a new Pipeline.
func New(cfg *config.Config, logger *slog.Logger) *Pipeline {
	return &Pipeline{
		cfg:    cfg,
		logger: logger,
	}
}

// AddStage appends a stage to the pipeline.
func (p *Pipeline) AddStage(s Stage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stages = append(p.stages, s)
}

// Run starts all stages in order. If any stage fails to start, previously
// started stages are stopped in reverse order and the original error is
// returned.
func (p *Pipeline) Run(ctx context.Context) error {
	p.mu.Lock()
	stages := make([]Stage, len(p.stages))
	copy(stages, p.stages)
	p.mu.Unlock()

	var started []Stage
	for _, s := range stages {
		p.logger.Info("starting stage", "stage", s.Name())
		if err := s.Start(ctx); err != nil {
			p.logger.Error("stage failed to start", "stage", s.Name(), "err", err)
			// Roll back already-started stages in reverse order.
			if rbErr := stopInReverse(ctx, started, p.logger); rbErr != nil {
				p.logger.Error("rollback error during startup failure", "err", rbErr)
			}
			return fmt.Errorf("start stage %s: %w", s.Name(), err)
		}
		started = append(started, s)
	}

	p.logger.Info("pipeline running", "stages", len(started))
	return nil
}

// Shutdown stops all stages in reverse order. It returns the first error
// encountered but still attempts to stop every stage.
func (p *Pipeline) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	stages := make([]Stage, len(p.stages))
	copy(stages, p.stages)
	p.mu.Unlock()

	return stopInReverse(ctx, stages, p.logger)
}

// stopInReverse stops stages from last to first, logging each step.
func stopInReverse(ctx context.Context, stages []Stage, logger *slog.Logger) error {
	var firstErr error
	for i := len(stages) - 1; i >= 0; i-- {
		s := stages[i]
		logger.Info("stopping stage", "stage", s.Name())
		if err := s.Stop(ctx); err != nil {
			logger.Error("stage stop error", "stage", s.Name(), "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
