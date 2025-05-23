// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/so/ent/cooperativeexit"
	"github.com/lightsparkdev/spark/so/ent/predicate"
	"github.com/lightsparkdev/spark/so/ent/transfer"
)

// CooperativeExitQuery is the builder for querying CooperativeExit entities.
type CooperativeExitQuery struct {
	config
	ctx          *QueryContext
	order        []cooperativeexit.OrderOption
	inters       []Interceptor
	predicates   []predicate.CooperativeExit
	withTransfer *TransferQuery
	withFKs      bool
	modifiers    []func(*sql.Selector)
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the CooperativeExitQuery builder.
func (ceq *CooperativeExitQuery) Where(ps ...predicate.CooperativeExit) *CooperativeExitQuery {
	ceq.predicates = append(ceq.predicates, ps...)
	return ceq
}

// Limit the number of records to be returned by this query.
func (ceq *CooperativeExitQuery) Limit(limit int) *CooperativeExitQuery {
	ceq.ctx.Limit = &limit
	return ceq
}

// Offset to start from.
func (ceq *CooperativeExitQuery) Offset(offset int) *CooperativeExitQuery {
	ceq.ctx.Offset = &offset
	return ceq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (ceq *CooperativeExitQuery) Unique(unique bool) *CooperativeExitQuery {
	ceq.ctx.Unique = &unique
	return ceq
}

// Order specifies how the records should be ordered.
func (ceq *CooperativeExitQuery) Order(o ...cooperativeexit.OrderOption) *CooperativeExitQuery {
	ceq.order = append(ceq.order, o...)
	return ceq
}

// QueryTransfer chains the current query on the "transfer" edge.
func (ceq *CooperativeExitQuery) QueryTransfer() *TransferQuery {
	query := (&TransferClient{config: ceq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := ceq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := ceq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(cooperativeexit.Table, cooperativeexit.FieldID, selector),
			sqlgraph.To(transfer.Table, transfer.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, cooperativeexit.TransferTable, cooperativeexit.TransferColumn),
		)
		fromU = sqlgraph.SetNeighbors(ceq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first CooperativeExit entity from the query.
// Returns a *NotFoundError when no CooperativeExit was found.
func (ceq *CooperativeExitQuery) First(ctx context.Context) (*CooperativeExit, error) {
	nodes, err := ceq.Limit(1).All(setContextOp(ctx, ceq.ctx, ent.OpQueryFirst))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{cooperativeexit.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (ceq *CooperativeExitQuery) FirstX(ctx context.Context) *CooperativeExit {
	node, err := ceq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first CooperativeExit ID from the query.
// Returns a *NotFoundError when no CooperativeExit ID was found.
func (ceq *CooperativeExitQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = ceq.Limit(1).IDs(setContextOp(ctx, ceq.ctx, ent.OpQueryFirstID)); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{cooperativeexit.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (ceq *CooperativeExitQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := ceq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single CooperativeExit entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one CooperativeExit entity is found.
// Returns a *NotFoundError when no CooperativeExit entities are found.
func (ceq *CooperativeExitQuery) Only(ctx context.Context) (*CooperativeExit, error) {
	nodes, err := ceq.Limit(2).All(setContextOp(ctx, ceq.ctx, ent.OpQueryOnly))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{cooperativeexit.Label}
	default:
		return nil, &NotSingularError{cooperativeexit.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (ceq *CooperativeExitQuery) OnlyX(ctx context.Context) *CooperativeExit {
	node, err := ceq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only CooperativeExit ID in the query.
// Returns a *NotSingularError when more than one CooperativeExit ID is found.
// Returns a *NotFoundError when no entities are found.
func (ceq *CooperativeExitQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = ceq.Limit(2).IDs(setContextOp(ctx, ceq.ctx, ent.OpQueryOnlyID)); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{cooperativeexit.Label}
	default:
		err = &NotSingularError{cooperativeexit.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (ceq *CooperativeExitQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := ceq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of CooperativeExits.
func (ceq *CooperativeExitQuery) All(ctx context.Context) ([]*CooperativeExit, error) {
	ctx = setContextOp(ctx, ceq.ctx, ent.OpQueryAll)
	if err := ceq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*CooperativeExit, *CooperativeExitQuery]()
	return withInterceptors[[]*CooperativeExit](ctx, ceq, qr, ceq.inters)
}

// AllX is like All, but panics if an error occurs.
func (ceq *CooperativeExitQuery) AllX(ctx context.Context) []*CooperativeExit {
	nodes, err := ceq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of CooperativeExit IDs.
func (ceq *CooperativeExitQuery) IDs(ctx context.Context) (ids []uuid.UUID, err error) {
	if ceq.ctx.Unique == nil && ceq.path != nil {
		ceq.Unique(true)
	}
	ctx = setContextOp(ctx, ceq.ctx, ent.OpQueryIDs)
	if err = ceq.Select(cooperativeexit.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (ceq *CooperativeExitQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := ceq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (ceq *CooperativeExitQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, ceq.ctx, ent.OpQueryCount)
	if err := ceq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, ceq, querierCount[*CooperativeExitQuery](), ceq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (ceq *CooperativeExitQuery) CountX(ctx context.Context) int {
	count, err := ceq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (ceq *CooperativeExitQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, ceq.ctx, ent.OpQueryExist)
	switch _, err := ceq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (ceq *CooperativeExitQuery) ExistX(ctx context.Context) bool {
	exist, err := ceq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the CooperativeExitQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (ceq *CooperativeExitQuery) Clone() *CooperativeExitQuery {
	if ceq == nil {
		return nil
	}
	return &CooperativeExitQuery{
		config:       ceq.config,
		ctx:          ceq.ctx.Clone(),
		order:        append([]cooperativeexit.OrderOption{}, ceq.order...),
		inters:       append([]Interceptor{}, ceq.inters...),
		predicates:   append([]predicate.CooperativeExit{}, ceq.predicates...),
		withTransfer: ceq.withTransfer.Clone(),
		// clone intermediate query.
		sql:  ceq.sql.Clone(),
		path: ceq.path,
	}
}

// WithTransfer tells the query-builder to eager-load the nodes that are connected to
// the "transfer" edge. The optional arguments are used to configure the query builder of the edge.
func (ceq *CooperativeExitQuery) WithTransfer(opts ...func(*TransferQuery)) *CooperativeExitQuery {
	query := (&TransferClient{config: ceq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	ceq.withTransfer = query
	return ceq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		CreateTime time.Time `json:"create_time,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.CooperativeExit.Query().
//		GroupBy(cooperativeexit.FieldCreateTime).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (ceq *CooperativeExitQuery) GroupBy(field string, fields ...string) *CooperativeExitGroupBy {
	ceq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &CooperativeExitGroupBy{build: ceq}
	grbuild.flds = &ceq.ctx.Fields
	grbuild.label = cooperativeexit.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		CreateTime time.Time `json:"create_time,omitempty"`
//	}
//
//	client.CooperativeExit.Query().
//		Select(cooperativeexit.FieldCreateTime).
//		Scan(ctx, &v)
func (ceq *CooperativeExitQuery) Select(fields ...string) *CooperativeExitSelect {
	ceq.ctx.Fields = append(ceq.ctx.Fields, fields...)
	sbuild := &CooperativeExitSelect{CooperativeExitQuery: ceq}
	sbuild.label = cooperativeexit.Label
	sbuild.flds, sbuild.scan = &ceq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a CooperativeExitSelect configured with the given aggregations.
func (ceq *CooperativeExitQuery) Aggregate(fns ...AggregateFunc) *CooperativeExitSelect {
	return ceq.Select().Aggregate(fns...)
}

func (ceq *CooperativeExitQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range ceq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, ceq); err != nil {
				return err
			}
		}
	}
	for _, f := range ceq.ctx.Fields {
		if !cooperativeexit.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if ceq.path != nil {
		prev, err := ceq.path(ctx)
		if err != nil {
			return err
		}
		ceq.sql = prev
	}
	return nil
}

func (ceq *CooperativeExitQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*CooperativeExit, error) {
	var (
		nodes       = []*CooperativeExit{}
		withFKs     = ceq.withFKs
		_spec       = ceq.querySpec()
		loadedTypes = [1]bool{
			ceq.withTransfer != nil,
		}
	)
	if ceq.withTransfer != nil {
		withFKs = true
	}
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, cooperativeexit.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*CooperativeExit).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &CooperativeExit{config: ceq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	if len(ceq.modifiers) > 0 {
		_spec.Modifiers = ceq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, ceq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := ceq.withTransfer; query != nil {
		if err := ceq.loadTransfer(ctx, query, nodes, nil,
			func(n *CooperativeExit, e *Transfer) { n.Edges.Transfer = e }); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (ceq *CooperativeExitQuery) loadTransfer(ctx context.Context, query *TransferQuery, nodes []*CooperativeExit, init func(*CooperativeExit), assign func(*CooperativeExit, *Transfer)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*CooperativeExit)
	for i := range nodes {
		if nodes[i].cooperative_exit_transfer == nil {
			continue
		}
		fk := *nodes[i].cooperative_exit_transfer
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(transfer.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "cooperative_exit_transfer" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (ceq *CooperativeExitQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := ceq.querySpec()
	if len(ceq.modifiers) > 0 {
		_spec.Modifiers = ceq.modifiers
	}
	_spec.Node.Columns = ceq.ctx.Fields
	if len(ceq.ctx.Fields) > 0 {
		_spec.Unique = ceq.ctx.Unique != nil && *ceq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, ceq.driver, _spec)
}

func (ceq *CooperativeExitQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(cooperativeexit.Table, cooperativeexit.Columns, sqlgraph.NewFieldSpec(cooperativeexit.FieldID, field.TypeUUID))
	_spec.From = ceq.sql
	if unique := ceq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if ceq.path != nil {
		_spec.Unique = true
	}
	if fields := ceq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, cooperativeexit.FieldID)
		for i := range fields {
			if fields[i] != cooperativeexit.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := ceq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := ceq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := ceq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := ceq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (ceq *CooperativeExitQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(ceq.driver.Dialect())
	t1 := builder.Table(cooperativeexit.Table)
	columns := ceq.ctx.Fields
	if len(columns) == 0 {
		columns = cooperativeexit.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if ceq.sql != nil {
		selector = ceq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if ceq.ctx.Unique != nil && *ceq.ctx.Unique {
		selector.Distinct()
	}
	for _, m := range ceq.modifiers {
		m(selector)
	}
	for _, p := range ceq.predicates {
		p(selector)
	}
	for _, p := range ceq.order {
		p(selector)
	}
	if offset := ceq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := ceq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// ForUpdate locks the selected rows against concurrent updates, and prevent them from being
// updated, deleted or "selected ... for update" by other sessions, until the transaction is
// either committed or rolled-back.
func (ceq *CooperativeExitQuery) ForUpdate(opts ...sql.LockOption) *CooperativeExitQuery {
	if ceq.driver.Dialect() == dialect.Postgres {
		ceq.Unique(false)
	}
	ceq.modifiers = append(ceq.modifiers, func(s *sql.Selector) {
		s.ForUpdate(opts...)
	})
	return ceq
}

// ForShare behaves similarly to ForUpdate, except that it acquires a shared mode lock
// on any rows that are read. Other sessions can read the rows, but cannot modify them
// until your transaction commits.
func (ceq *CooperativeExitQuery) ForShare(opts ...sql.LockOption) *CooperativeExitQuery {
	if ceq.driver.Dialect() == dialect.Postgres {
		ceq.Unique(false)
	}
	ceq.modifiers = append(ceq.modifiers, func(s *sql.Selector) {
		s.ForShare(opts...)
	})
	return ceq
}

// CooperativeExitGroupBy is the group-by builder for CooperativeExit entities.
type CooperativeExitGroupBy struct {
	selector
	build *CooperativeExitQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (cegb *CooperativeExitGroupBy) Aggregate(fns ...AggregateFunc) *CooperativeExitGroupBy {
	cegb.fns = append(cegb.fns, fns...)
	return cegb
}

// Scan applies the selector query and scans the result into the given value.
func (cegb *CooperativeExitGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, cegb.build.ctx, ent.OpQueryGroupBy)
	if err := cegb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*CooperativeExitQuery, *CooperativeExitGroupBy](ctx, cegb.build, cegb, cegb.build.inters, v)
}

func (cegb *CooperativeExitGroupBy) sqlScan(ctx context.Context, root *CooperativeExitQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(cegb.fns))
	for _, fn := range cegb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*cegb.flds)+len(cegb.fns))
		for _, f := range *cegb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*cegb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := cegb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// CooperativeExitSelect is the builder for selecting fields of CooperativeExit entities.
type CooperativeExitSelect struct {
	*CooperativeExitQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (ces *CooperativeExitSelect) Aggregate(fns ...AggregateFunc) *CooperativeExitSelect {
	ces.fns = append(ces.fns, fns...)
	return ces
}

// Scan applies the selector query and scans the result into the given value.
func (ces *CooperativeExitSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, ces.ctx, ent.OpQuerySelect)
	if err := ces.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*CooperativeExitQuery, *CooperativeExitSelect](ctx, ces.CooperativeExitQuery, ces, ces.inters, v)
}

func (ces *CooperativeExitSelect) sqlScan(ctx context.Context, root *CooperativeExitQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(ces.fns))
	for _, fn := range ces.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*ces.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := ces.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
