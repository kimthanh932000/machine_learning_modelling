#install.packages(c("tidyverse","moments","ggpubr", "forcats", "caret"))  #De-comment the code to install
library("tidyverse"); library(moments); library(ggpubr); library(forcats); library(caret)

#PART_01
#=========================================================
#a) Import the master dataset
df <- read.csv("WACY-COM.csv", na.strings=NA, stringsAsFactors=TRUE)

# A vector contains all categorical variables
categorical.vars <- c(
  "Port",
  "Protocol",
  "Target.Honeypot.Server.OS",
  "Source.OS.Detected",
  "Source.Port.Range",
  "Source.IP.Type.Detected"
)

# Convert each categorical variable to a factor 
for (var in categorical.vars) {
  df[[var]] <- factor(df[[var]])
}

#=========================================================
#b.i) 
# Remove "IP.Range.Trust.Score" from further analysis (>80% missing value)
df$IP.Range.Trust.Score <- NULL

# Remove "Source.Port.Range" from further analysis (>30% missing value)
df$Source.Port.Range <- NULL

# Mask negative value (-1) in "Attack.Source.IP.Address"
df$Attack.Source.IP.Address.Count[df$Attack.Source.IP.Address.Count < 0] <- NA

# Mask extreme value (99999) in "Average.ping.to.attacking.IP.milliseconds"
df$Average.ping.to.attacking.IP.milliseconds[df$Average.ping.to.attacking.IP.milliseconds == 99999] <- NA

# Mask "???" value in "Source.OS.Detected" (1.2%)
df$Source.OS.Detected[df$Source.OS.Detected == "???"] <- NA

#=======================================================
#b.ii)
# For "Source.OS.Detected", merge "Windows 10" and "Windows Server 2008" into a new category named "Windows_All"
df$Source.OS.Detected <- fct_collapse(
  df$Source.OS.Detected,
  Windows_All = c("Windows 10", "Windows Server 2008")
)

# For "Target.Honeypot.Server.OS", merge "Windows (Desktops)" and "Windows (Servers)" into a new category named "Windows_All"
df$Target.Honeypot.Server.OS <- fct_collapse(
  df$Target.Honeypot.Server.OS,
  Windows_DeskServ = c("Windows (Desktops)", "Windows (Servers)")
)

# Further merge "Linux" and "MacOS (All)" into a new category named "MacOS_Linux"
df$Target.Honeypot.Server.OS <- fct_collapse(
  df$Target.Honeypot.Server.OS,
  MacOS_Linux = c("Linux", "MacOS (All)")
)

#=========================================================
#b.iii)
# Log-transform "Average.ping.variability"
for (col in c("Average.ping.variability")) {
  df[[col]] <- log(df[[col]])
}

# Square-root transform following:
# 1. Hits;
# 2. Attack.Source.IP.Address.Count;
# 3. Average.ping.to.attacking.IP.milliseconds;
# 4. Individual.URLs.requested.
for (col in c(
  "Hits",
  "Attack.Source.IP.Address.Count",
  "Average.ping.to.attacking.IP.milliseconds",
  "Individual.URLs.requested")) {
  df[[col]] <- sqrt(df[[col]])
}

#======================================================
#b.iv)
#Remove incomplete cases and name the dataset "WACY-COM_cleaned"
WACY_COM_cleaned <- na.omit(df)

#===================================================
#c) Partition the dataset into train and test sets using 30/70 split
set.seed(10657323)

# Step 1: Get row numbers for the training data
trainRowNumbers <- createDataPartition(WACY_COM_cleaned$APT, #The outcome variable
                                       p=0.30, #proportion of data to form the training set
                                       list=FALSE #Don't store the result in a list
);
# Step 2: Create the training dataset
trainData <- WACY_COM_cleaned[trainRowNumbers,]

# Step 3: Create the test dataset
testData <- WACY_COM_cleaned[-trainRowNumbers,]

# Export train set
write.csv(trainData, "trainData.csv", row.names = FALSE)

# Export test set
write.csv(testData, "testData.csv", row.names = FALSE)


