# ================= UPDATED IMPORTS FOR FINE-TUNING =================
from transformers import (
    AutoTokenizer, 
    AutoModelForCausalLM, 
    BitsAndBytesConfig,
    Trainer,
    TrainingArguments,
    DataCollatorForSeq2Seq
)
import os
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training  # <-- NEW
from torch.utils.data import Dataset
os.environ["HUGGINGFACE_HUB_TOKEN"] = "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"

# ================= NEW DATASET CLASS FOR FINE-TUNING =================
class VulnerabilityFixDataset(Dataset):
    """Dataset for fine-tuning on vulnerability fixes"""
    def __init__(self, data_list, tokenizer, max_length=1024):
        """
        data_list: List of dicts with {"prompt": ..., "target": ...}
        tokenizer: HuggingFace tokenizer
        """
        self.tokenizer = tokenizer
        self.data = data_list
        self.max_length = max_length

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        item = self.data[idx]
        prompt = item['prompt']
        target = item['target']

        # Concatenate prompt and target for causal LM fine-tuning
        input_text = prompt + target
        encoding = self.tokenizer(
            input_text,
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt"
        )
        # Flatten tensors
        input_ids = encoding['input_ids'].squeeze()
        attention_mask = encoding['attention_mask'].squeeze()

        # Labels same as input_ids for causal LM
        labels = input_ids.clone()

        return {
            'input_ids': input_ids,
            'attention_mask': attention_mask,
            'labels': labels
        }


# ================= MODIFIED MODEL CLASS FOR FINE-TUNING =================
class VulnerabilityFixerModel:
    
    def __init__(self, model_name):
        print(f"Loading model: {model_name}")
        
        # bnb_config = BitsAndBytesConfig(
        #     load_in_4bit=True,
        #     bnb_4bit_use_double_quant=True,
        #     bnb_4bit_quant_type="nf4",
        #     bnb_4bit_compute_dtype=torch.bfloat16
        # )
        local_model_path = "../models/" + model_name
        self.tokenizer = AutoTokenizer.from_pretrained(model_name, cache_dir=local_model_path, use_auth_token=os.environ["HUGGINGFACE_HUB_TOKEN"])
        self.tokenizer.pad_token = self.tokenizer.eos_token
        
        # Load pre-trained model
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name,
            device_map="auto",
            trust_remote_code=True,
            cache_dir=local_model_path,
            use_auth_token=os.environ["HUGGINGFACE_HUB_TOKEN"]
        )

        # ================== NEW: PREPARE MODEL FOR LORA ==================
        self.enable_finetune = True  # Set to True to enable fine-tuning
        if self.enable_finetune:
            self.model = prepare_model_for_kbit_training(self.model)
            lora_config = LoraConfig(
                r=16,
                lora_alpha=32,
                # target_modules=["q_proj", "v_proj"],  # typical for LLMs
                target_modules=["c_attn", "c_proj"],  # GPT-2 specific
                lora_dropout=0.05,
                bias="none",
                task_type="CAUSAL_LM"
            )
            self.model = get_peft_model(self.model, lora_config)
            print("Model prepared for LoRA fine-tuning")

    # ================== FINE-TUNING METHOD ==================
    def fine_tune(self, dataset_list, output_dir, epochs=3, batch_size=1):
        dataset = VulnerabilityFixDataset(dataset_list, self.tokenizer)
        data_collator = DataCollatorForSeq2Seq(tokenizer=self.tokenizer, return_tensors="pt")
        
        training_args = TrainingArguments(
            output_dir=output_dir,
            per_device_train_batch_size=batch_size,
            num_train_epochs=epochs,
            learning_rate=2e-4,
            logging_steps=10,
            save_strategy="epoch",
            save_total_limit=2,
            gradient_accumulation_steps=8,
            report_to="none",
            bf16=False,   
            fp16=False
        )
        
        trainer = Trainer(
            model=self.model,
            train_dataset=dataset,
            tokenizer=self.tokenizer,
            data_collator=data_collator,
            args=training_args
        )
        
        print("Starting fine-tuning...")
        trainer.train()
        print(f"Fine-tuning completed. Model saved to {output_dir}")
        
        # Save LoRA adapters
        self.model.save_pretrained(output_dir)


# 1. Initialize with fine-tuning enabled
model = VulnerabilityFixerModel("bigcode/starcoderbase-1b")

# 2. Prepare your training dataset
train_data = [
    {
        "prompt": "VULNERABILITY DETAILS:\nType: SQL Injection\nCODE TO FIX:\n```java\nString query = \"SELECT * FROM users WHERE id = \" + userId;\n```\nTASK:\nFix it.\n",
        "target": "FIXED_CODE:\n```java\nString query = \"SELECT * FROM users WHERE id = ?\";\nPreparedStatement pstmt = connection.prepareStatement(query);\npstmt.setString(1, userId);\n```"
    }
]

# 3. Fine-tune
model.fine_tune(train_data, output_dir="../models/fine_tunning", epochs=3, batch_size=1)