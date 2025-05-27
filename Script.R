install.packages(c("tidyverse","moments","ggpubr", "forcats", "caret", "glmnet", "ipred", "ranger", "rpart"))  #De-comment the code to install
library(tidyverse);
library(moments);
library(ggpubr);
library(forcats);
library(caret);
library(glmnet);
library(ipred);
library(ranger);
library(rpart);

student.id <- 10657323

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
set.seed(student.id)

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

#===================================================
#PART_02
#==================================================
#a) Select randomly THREE training models
set.seed(student.id)
models.list1 <- c("Logistic Ridge Regression",
                  "Logistic LASSO Regression",
                  "Logistic Elastic-Net Regression")
models.list2 <- c("Classification Tree",
                  "Bagging Tree",
                  "Random Forest")
myModels <- c(sample(models.list1,size=1),
              sample(models.list2,size=2))
myModels %>% data.frame

#=======================================
#b) LASSO Regression
lambdas <- 10^seq(-3,3,length=100) #A sequence of lambdas

set.seed(student.id)
mod.LASSO <- train(APT ~., #Formula
                   data = trainData, #Training data
                   method = "glmnet", #Penalised regression modelling
                   #Set preProcess to c("center", "scale") to standardise data
                   preProcess = NULL,
                   #Perform 10-fold CV, 2 times over.
                   trControl = trainControl("repeatedcv",
                                            number = 10,
                                            repeats = 2),
                   tuneGrid = expand.grid(alpha = 1, #LASSO regression
                                          lambda = lambdas)
)
#Optimal lambda value
mod.LASSO$bestTune

# Model coefficients
coef(mod.LASSO$finalModel, mod.LASSO$bestTune$lambda)

# Predict classes of APT on the test data
pred.class.LASSO <- predict(mod.LASSO,new=testData) 

# Confusion matrix with re-ordering of "Yes" and "No" responses
cf.LASSO <- table(pred.class.LASSO %>% relevel(ref="Yes"),
                  testData$APT %>% relevel(ref="Yes"));

prop <- prop.table(cf.LASSO,2); prop %>% round(digit=3) #Proportions by columns

#Summary of confusion matrix
confusionMatrix(cf.LASSO)

#===================================================
#b) Bagging

#Intialise the hyperparamter search grid
grid.bc <- expand.grid(nbagg=seq(15,35,10), #A sequence of nbagg values
                       cp=seq(0.0055,0.0145,0.0045), #A sequence of cp values
                       minsplit=seq(10,30,10), #A sequence of minsplits values
                       #Initialise columns to store the OOB misclassification rate
                       OOB.misclass=NA,
                       #Initialise columns to store sensitivity, specificity and
                       #accuracy of bagging at each run.
                       test.sens=NA,
                       test.spec=NA,
                       test.acc=NA)


# Display the search grid
View(grid.bc)

for (I in 1:nrow(grid.bc))
{
  set.seed(student.id)
  #Perform bagging
  btree.bc <- bagging(APT~.,
                      data=trainData,
                      nbagg=grid.bc$nbagg[I],
                      coob=TRUE,
                      control=rpart.control(cp=grid.bc$cp[I],
                                            minsplit=grid.bc$minsplit[I]));
  #OOB misclassification rate
  grid.bc$OOB.misclass[I] <- btree.bc$err*100
  #Summary of predictions on test set
  test.pred.bc <- predict(btree.bc,newdata=testData,type="class"); #Class prediction
  #Confusion matrix
  test.cf.bc <- confusionMatrix(test.pred.bc %>% relevel(ref="Yes"),
                                testData$APT %>% relevel(ref="Yes"))
  prop.cf.bc <- test.cf.bc$table %>% prop.table(2)
  grid.bc$test.sens[I] <- prop.cf.bc[1,1]*100 #Sensitivity
  grid.bc$test.spec[I] <- prop.cf.bc[2,2]*100 #Specificity
  grid.bc$test.acc[I] <- test.cf.bc$overall[1]*100 #Accuracy
  
  cat("Iteration", I, 
      "- nbagg:", grid.bc$nbagg[I], 
      "- cp:", grid.bc$cp[I], 
      "- minsplit:", grid.bc$minsplit[I], "\n",
      "OOB Misclass:", round(grid.bc$OOB.misclass[I], 2), "%",
      "- Accuracy:", round(grid.bc$test.acc[I], 2), "%",
      "- Sensitivity:", round(grid.bc$test.sens[I], 2), "%",
      "- Specificity:", round(grid.bc$test.spec[I], 2), "%\n\n")
}


#Sort the results by the OOB misclassification rate and display them.
grid.bc[order(grid.bc$OOB.misclass,decreasing=FALSE)[1:10],] %>% round(2)

