/* Type picker — choose what kind of cipher to add.
 *
 * Mirrors the popup's renderTypePicker. API ciphers (type 7) are
 * intentionally not in the picker: they exist on the wire but no
 * popup/web flow creates them today (popup parity).
 */
import { For } from "solid-js";

import { ADD_PICKER_ORDER, CIPHER_TYPE_DEFS } from "../../lib/cipher";
import { iconForCipherType } from "../../ui/icons";
import { SubShell } from "../../ui/Shell";

export interface TypePickerProps {
  onSelect: (type: number) => void;
  onBack: () => void;
}

export function TypePicker(props: TypePickerProps) {
  return (
    <SubShell title="New item" onBack={props.onBack}>
      <p class="muted" style="margin: 0 0 1rem;">
        Pick what kind of vault item to add.
      </p>
      <div
        style="display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 0.75rem;"
      >
        <For each={ADD_PICKER_ORDER}>
          {(typeId) => {
            const def = CIPHER_TYPE_DEFS[typeId];
            const Icon = iconForCipherType(typeId);
            return (
              <button
                type="button"
                class="card"
                style="display: flex; align-items: center; gap: 0.75rem; cursor: pointer; text-align: left;"
                onClick={() => props.onSelect(typeId)}
              >
                <span class="row-icon" data-type={typeId}>
                  <Icon />
                </span>
                <div>
                  <div style="font-weight: 500;">{def.label}</div>
                  <div class="muted" style="font-size: 0.8rem;">
                    {summaryFor(typeId)}
                  </div>
                </div>
              </button>
            );
          }}
        </For>
      </div>
    </SubShell>
  );
}

function summaryFor(type: number): string {
  switch (type) {
    case 1:
      return "Username + password";
    case 2:
      return "Encrypted free-text note";
    case 3:
      return "Credit / debit card";
    case 4:
      return "Personal identity record";
    case 5:
      return "SSH keypair";
    case 6:
      return "Time-based one-time password";
    default:
      return "";
  }
}
