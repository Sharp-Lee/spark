// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/so/ent/schema"
	"github.com/lightsparkdev/spark/so/ent/signingkeyshare"
	"github.com/lightsparkdev/spark/so/ent/tokenoutput"
	"github.com/lightsparkdev/spark/so/ent/tokentransaction"
)

// TokenOutput is the model entity for the TokenOutput schema.
type TokenOutput struct {
	config `json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// CreateTime holds the value of the "create_time" field.
	CreateTime time.Time `json:"create_time,omitempty"`
	// UpdateTime holds the value of the "update_time" field.
	UpdateTime time.Time `json:"update_time,omitempty"`
	// Status holds the value of the "status" field.
	Status schema.TokenOutputStatus `json:"status,omitempty"`
	// OwnerPublicKey holds the value of the "owner_public_key" field.
	OwnerPublicKey []byte `json:"owner_public_key,omitempty"`
	// WithdrawBondSats holds the value of the "withdraw_bond_sats" field.
	WithdrawBondSats uint64 `json:"withdraw_bond_sats,omitempty"`
	// WithdrawRelativeBlockLocktime holds the value of the "withdraw_relative_block_locktime" field.
	WithdrawRelativeBlockLocktime uint64 `json:"withdraw_relative_block_locktime,omitempty"`
	// WithdrawRevocationCommitment holds the value of the "withdraw_revocation_commitment" field.
	WithdrawRevocationCommitment []byte `json:"withdraw_revocation_commitment,omitempty"`
	// TokenPublicKey holds the value of the "token_public_key" field.
	TokenPublicKey []byte `json:"token_public_key,omitempty"`
	// TokenAmount holds the value of the "token_amount" field.
	TokenAmount []byte `json:"token_amount,omitempty"`
	// CreatedTransactionOutputVout holds the value of the "created_transaction_output_vout" field.
	CreatedTransactionOutputVout int32 `json:"created_transaction_output_vout,omitempty"`
	// SpentOwnershipSignature holds the value of the "spent_ownership_signature" field.
	SpentOwnershipSignature []byte `json:"spent_ownership_signature,omitempty"`
	// SpentOperatorSpecificOwnershipSignature holds the value of the "spent_operator_specific_ownership_signature" field.
	SpentOperatorSpecificOwnershipSignature []byte `json:"spent_operator_specific_ownership_signature,omitempty"`
	// SpentTransactionInputVout holds the value of the "spent_transaction_input_vout" field.
	SpentTransactionInputVout int32 `json:"spent_transaction_input_vout,omitempty"`
	// SpentRevocationSecret holds the value of the "spent_revocation_secret" field.
	SpentRevocationSecret []byte `json:"spent_revocation_secret,omitempty"`
	// ConfirmedWithdrawBlockHash holds the value of the "confirmed_withdraw_block_hash" field.
	ConfirmedWithdrawBlockHash []byte `json:"confirmed_withdraw_block_hash,omitempty"`
	// Network holds the value of the "network" field.
	Network schema.Network `json:"network,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the TokenOutputQuery when eager-loading is set.
	Edges                                         TokenOutputEdges `json:"edges"`
	token_output_revocation_keyshare              *uuid.UUID
	token_output_output_created_token_transaction *uuid.UUID
	token_output_output_spent_token_transaction   *uuid.UUID
	selectValues                                  sql.SelectValues
}

// TokenOutputEdges holds the relations/edges for other nodes in the graph.
type TokenOutputEdges struct {
	// RevocationKeyshare holds the value of the revocation_keyshare edge.
	RevocationKeyshare *SigningKeyshare `json:"revocation_keyshare,omitempty"`
	// OutputCreatedTokenTransaction holds the value of the output_created_token_transaction edge.
	OutputCreatedTokenTransaction *TokenTransaction `json:"output_created_token_transaction,omitempty"`
	// OutputSpentTokenTransaction holds the value of the output_spent_token_transaction edge.
	OutputSpentTokenTransaction *TokenTransaction `json:"output_spent_token_transaction,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [3]bool
}

// RevocationKeyshareOrErr returns the RevocationKeyshare value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e TokenOutputEdges) RevocationKeyshareOrErr() (*SigningKeyshare, error) {
	if e.RevocationKeyshare != nil {
		return e.RevocationKeyshare, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: signingkeyshare.Label}
	}
	return nil, &NotLoadedError{edge: "revocation_keyshare"}
}

// OutputCreatedTokenTransactionOrErr returns the OutputCreatedTokenTransaction value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e TokenOutputEdges) OutputCreatedTokenTransactionOrErr() (*TokenTransaction, error) {
	if e.OutputCreatedTokenTransaction != nil {
		return e.OutputCreatedTokenTransaction, nil
	} else if e.loadedTypes[1] {
		return nil, &NotFoundError{label: tokentransaction.Label}
	}
	return nil, &NotLoadedError{edge: "output_created_token_transaction"}
}

// OutputSpentTokenTransactionOrErr returns the OutputSpentTokenTransaction value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e TokenOutputEdges) OutputSpentTokenTransactionOrErr() (*TokenTransaction, error) {
	if e.OutputSpentTokenTransaction != nil {
		return e.OutputSpentTokenTransaction, nil
	} else if e.loadedTypes[2] {
		return nil, &NotFoundError{label: tokentransaction.Label}
	}
	return nil, &NotLoadedError{edge: "output_spent_token_transaction"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*TokenOutput) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case tokenoutput.FieldOwnerPublicKey, tokenoutput.FieldWithdrawRevocationCommitment, tokenoutput.FieldTokenPublicKey, tokenoutput.FieldTokenAmount, tokenoutput.FieldSpentOwnershipSignature, tokenoutput.FieldSpentOperatorSpecificOwnershipSignature, tokenoutput.FieldSpentRevocationSecret, tokenoutput.FieldConfirmedWithdrawBlockHash:
			values[i] = new([]byte)
		case tokenoutput.FieldWithdrawBondSats, tokenoutput.FieldWithdrawRelativeBlockLocktime, tokenoutput.FieldCreatedTransactionOutputVout, tokenoutput.FieldSpentTransactionInputVout:
			values[i] = new(sql.NullInt64)
		case tokenoutput.FieldStatus, tokenoutput.FieldNetwork:
			values[i] = new(sql.NullString)
		case tokenoutput.FieldCreateTime, tokenoutput.FieldUpdateTime:
			values[i] = new(sql.NullTime)
		case tokenoutput.FieldID:
			values[i] = new(uuid.UUID)
		case tokenoutput.ForeignKeys[0]: // token_output_revocation_keyshare
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case tokenoutput.ForeignKeys[1]: // token_output_output_created_token_transaction
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case tokenoutput.ForeignKeys[2]: // token_output_output_spent_token_transaction
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the TokenOutput fields.
func (to *TokenOutput) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case tokenoutput.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				to.ID = *value
			}
		case tokenoutput.FieldCreateTime:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field create_time", values[i])
			} else if value.Valid {
				to.CreateTime = value.Time
			}
		case tokenoutput.FieldUpdateTime:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field update_time", values[i])
			} else if value.Valid {
				to.UpdateTime = value.Time
			}
		case tokenoutput.FieldStatus:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field status", values[i])
			} else if value.Valid {
				to.Status = schema.TokenOutputStatus(value.String)
			}
		case tokenoutput.FieldOwnerPublicKey:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field owner_public_key", values[i])
			} else if value != nil {
				to.OwnerPublicKey = *value
			}
		case tokenoutput.FieldWithdrawBondSats:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field withdraw_bond_sats", values[i])
			} else if value.Valid {
				to.WithdrawBondSats = uint64(value.Int64)
			}
		case tokenoutput.FieldWithdrawRelativeBlockLocktime:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field withdraw_relative_block_locktime", values[i])
			} else if value.Valid {
				to.WithdrawRelativeBlockLocktime = uint64(value.Int64)
			}
		case tokenoutput.FieldWithdrawRevocationCommitment:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field withdraw_revocation_commitment", values[i])
			} else if value != nil {
				to.WithdrawRevocationCommitment = *value
			}
		case tokenoutput.FieldTokenPublicKey:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field token_public_key", values[i])
			} else if value != nil {
				to.TokenPublicKey = *value
			}
		case tokenoutput.FieldTokenAmount:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field token_amount", values[i])
			} else if value != nil {
				to.TokenAmount = *value
			}
		case tokenoutput.FieldCreatedTransactionOutputVout:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field created_transaction_output_vout", values[i])
			} else if value.Valid {
				to.CreatedTransactionOutputVout = int32(value.Int64)
			}
		case tokenoutput.FieldSpentOwnershipSignature:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field spent_ownership_signature", values[i])
			} else if value != nil {
				to.SpentOwnershipSignature = *value
			}
		case tokenoutput.FieldSpentOperatorSpecificOwnershipSignature:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field spent_operator_specific_ownership_signature", values[i])
			} else if value != nil {
				to.SpentOperatorSpecificOwnershipSignature = *value
			}
		case tokenoutput.FieldSpentTransactionInputVout:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for field spent_transaction_input_vout", values[i])
			} else if value.Valid {
				to.SpentTransactionInputVout = int32(value.Int64)
			}
		case tokenoutput.FieldSpentRevocationSecret:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field spent_revocation_secret", values[i])
			} else if value != nil {
				to.SpentRevocationSecret = *value
			}
		case tokenoutput.FieldConfirmedWithdrawBlockHash:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field confirmed_withdraw_block_hash", values[i])
			} else if value != nil {
				to.ConfirmedWithdrawBlockHash = *value
			}
		case tokenoutput.FieldNetwork:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field network", values[i])
			} else if value.Valid {
				to.Network = schema.Network(value.String)
			}
		case tokenoutput.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field token_output_revocation_keyshare", values[i])
			} else if value.Valid {
				to.token_output_revocation_keyshare = new(uuid.UUID)
				*to.token_output_revocation_keyshare = *value.S.(*uuid.UUID)
			}
		case tokenoutput.ForeignKeys[1]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field token_output_output_created_token_transaction", values[i])
			} else if value.Valid {
				to.token_output_output_created_token_transaction = new(uuid.UUID)
				*to.token_output_output_created_token_transaction = *value.S.(*uuid.UUID)
			}
		case tokenoutput.ForeignKeys[2]:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field token_output_output_spent_token_transaction", values[i])
			} else if value.Valid {
				to.token_output_output_spent_token_transaction = new(uuid.UUID)
				*to.token_output_output_spent_token_transaction = *value.S.(*uuid.UUID)
			}
		default:
			to.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the TokenOutput.
// This includes values selected through modifiers, order, etc.
func (to *TokenOutput) Value(name string) (ent.Value, error) {
	return to.selectValues.Get(name)
}

// QueryRevocationKeyshare queries the "revocation_keyshare" edge of the TokenOutput entity.
func (to *TokenOutput) QueryRevocationKeyshare() *SigningKeyshareQuery {
	return NewTokenOutputClient(to.config).QueryRevocationKeyshare(to)
}

// QueryOutputCreatedTokenTransaction queries the "output_created_token_transaction" edge of the TokenOutput entity.
func (to *TokenOutput) QueryOutputCreatedTokenTransaction() *TokenTransactionQuery {
	return NewTokenOutputClient(to.config).QueryOutputCreatedTokenTransaction(to)
}

// QueryOutputSpentTokenTransaction queries the "output_spent_token_transaction" edge of the TokenOutput entity.
func (to *TokenOutput) QueryOutputSpentTokenTransaction() *TokenTransactionQuery {
	return NewTokenOutputClient(to.config).QueryOutputSpentTokenTransaction(to)
}

// Update returns a builder for updating this TokenOutput.
// Note that you need to call TokenOutput.Unwrap() before calling this method if this TokenOutput
// was returned from a transaction, and the transaction was committed or rolled back.
func (to *TokenOutput) Update() *TokenOutputUpdateOne {
	return NewTokenOutputClient(to.config).UpdateOne(to)
}

// Unwrap unwraps the TokenOutput entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (to *TokenOutput) Unwrap() *TokenOutput {
	_tx, ok := to.config.driver.(*txDriver)
	if !ok {
		panic("ent: TokenOutput is not a transactional entity")
	}
	to.config.driver = _tx.drv
	return to
}

// String implements the fmt.Stringer.
func (to *TokenOutput) String() string {
	var builder strings.Builder
	builder.WriteString("TokenOutput(")
	builder.WriteString(fmt.Sprintf("id=%v, ", to.ID))
	builder.WriteString("create_time=")
	builder.WriteString(to.CreateTime.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("update_time=")
	builder.WriteString(to.UpdateTime.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("status=")
	builder.WriteString(fmt.Sprintf("%v", to.Status))
	builder.WriteString(", ")
	builder.WriteString("owner_public_key=")
	builder.WriteString(fmt.Sprintf("%v", to.OwnerPublicKey))
	builder.WriteString(", ")
	builder.WriteString("withdraw_bond_sats=")
	builder.WriteString(fmt.Sprintf("%v", to.WithdrawBondSats))
	builder.WriteString(", ")
	builder.WriteString("withdraw_relative_block_locktime=")
	builder.WriteString(fmt.Sprintf("%v", to.WithdrawRelativeBlockLocktime))
	builder.WriteString(", ")
	builder.WriteString("withdraw_revocation_commitment=")
	builder.WriteString(fmt.Sprintf("%v", to.WithdrawRevocationCommitment))
	builder.WriteString(", ")
	builder.WriteString("token_public_key=")
	builder.WriteString(fmt.Sprintf("%v", to.TokenPublicKey))
	builder.WriteString(", ")
	builder.WriteString("token_amount=")
	builder.WriteString(fmt.Sprintf("%v", to.TokenAmount))
	builder.WriteString(", ")
	builder.WriteString("created_transaction_output_vout=")
	builder.WriteString(fmt.Sprintf("%v", to.CreatedTransactionOutputVout))
	builder.WriteString(", ")
	builder.WriteString("spent_ownership_signature=")
	builder.WriteString(fmt.Sprintf("%v", to.SpentOwnershipSignature))
	builder.WriteString(", ")
	builder.WriteString("spent_operator_specific_ownership_signature=")
	builder.WriteString(fmt.Sprintf("%v", to.SpentOperatorSpecificOwnershipSignature))
	builder.WriteString(", ")
	builder.WriteString("spent_transaction_input_vout=")
	builder.WriteString(fmt.Sprintf("%v", to.SpentTransactionInputVout))
	builder.WriteString(", ")
	builder.WriteString("spent_revocation_secret=")
	builder.WriteString(fmt.Sprintf("%v", to.SpentRevocationSecret))
	builder.WriteString(", ")
	builder.WriteString("confirmed_withdraw_block_hash=")
	builder.WriteString(fmt.Sprintf("%v", to.ConfirmedWithdrawBlockHash))
	builder.WriteString(", ")
	builder.WriteString("network=")
	builder.WriteString(fmt.Sprintf("%v", to.Network))
	builder.WriteByte(')')
	return builder.String()
}

// TokenOutputs is a parsable slice of TokenOutput.
type TokenOutputs []*TokenOutput
