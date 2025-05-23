// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/so/ent/blockheight"
	"github.com/lightsparkdev/spark/so/ent/schema"
)

// BlockHeight is the model entity for the BlockHeight schema.
type BlockHeight struct {
	config `json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// CreateTime holds the value of the "create_time" field.
	CreateTime time.Time `json:"create_time,omitempty"`
	// UpdateTime holds the value of the "update_time" field.
	UpdateTime time.Time `json:"update_time,omitempty"`
	// Height holds the value of the "height" field.
	Height int64 `json:"height,omitempty"`
	// Network holds the value of the "network" field.
	Network      schema.Network `json:"network,omitempty"`
	selectValues sql.SelectValues
}

// scanValues returns the types for scanning values from sql.Rows.
func (*BlockHeight) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case blockheight.FieldHeight:
			values[i] = new(sql.NullInt64)
		case blockheight.FieldNetwork:
			values[i] = new(sql.NullString)
		case blockheight.FieldCreateTime, blockheight.FieldUpdateTime:
			values[i] = new(sql.NullTime)
		case blockheight.FieldID:
			values[i] = new(uuid.UUID)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the BlockHeight fields.
func (bh *BlockHeight) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case blockheight.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				bh.ID = *value
			}
		case blockheight.FieldCreateTime:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field create_time", values[i])
			} else if value.Valid {
				bh.CreateTime = value.Time
			}
		case blockheight.FieldUpdateTime:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field update_time", values[i])
			} else if value.Valid {
				bh.UpdateTime = value.Time
			}
		case blockheight.FieldHeight:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field height", values[i])
			} else if value.Valid {
				bh.Height = value.Int64
			}
		case blockheight.FieldNetwork:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field network", values[i])
			} else if value.Valid {
				bh.Network = schema.Network(value.String)
			}
		default:
			bh.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the BlockHeight.
// This includes values selected through modifiers, order, etc.
func (bh *BlockHeight) Value(name string) (ent.Value, error) {
	return bh.selectValues.Get(name)
}

// Update returns a builder for updating this BlockHeight.
// Note that you need to call BlockHeight.Unwrap() before calling this method if this BlockHeight
// was returned from a transaction, and the transaction was committed or rolled back.
func (bh *BlockHeight) Update() *BlockHeightUpdateOne {
	return NewBlockHeightClient(bh.config).UpdateOne(bh)
}

// Unwrap unwraps the BlockHeight entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (bh *BlockHeight) Unwrap() *BlockHeight {
	_tx, ok := bh.config.driver.(*txDriver)
	if !ok {
		panic("ent: BlockHeight is not a transactional entity")
	}
	bh.config.driver = _tx.drv
	return bh
}

// String implements the fmt.Stringer.
func (bh *BlockHeight) String() string {
	var builder strings.Builder
	builder.WriteString("BlockHeight(")
	builder.WriteString(fmt.Sprintf("id=%v, ", bh.ID))
	builder.WriteString("create_time=")
	builder.WriteString(bh.CreateTime.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("update_time=")
	builder.WriteString(bh.UpdateTime.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("height=")
	builder.WriteString(fmt.Sprintf("%v", bh.Height))
	builder.WriteString(", ")
	builder.WriteString("network=")
	builder.WriteString(fmt.Sprintf("%v", bh.Network))
	builder.WriteByte(')')
	return builder.String()
}

// BlockHeights is a parsable slice of BlockHeight.
type BlockHeights []*BlockHeight
